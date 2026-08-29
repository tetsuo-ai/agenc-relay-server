---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 87 symbols across 16 files."
---

# Fuzz_targets

87 symbols | 16 files | Cohesion: 68%

## When to Use

- Working with code in `fuzz/`
- Understanding how as_str, parse_message, requested_backing_capacities work
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
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | parsed, classify, validate_account_length |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure, command_bytes, combined_tag_section |
| `crates/agenc-ircd-storage/src/sealed.rs` | new, seal, open |
| `fuzz/fuzz_targets/tcp_framing.rs` | run, checksum |

## Entry Points

Start here when exploring this area:

- **`as_str`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:86`
- **`parse_message`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:150`
- **`requested_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:208`
- **`measure`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:284`
- **`parse_u16_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:230`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `parse_message` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 150 |
| `requested_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 208 |
| `measure` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 284 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 369 |
| `request` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 269 |
| `from_reserved_bytes` | Function | `crates/agenc-ircd-crypto/src/storage.rs` | 171 |
| `derive_storage_record_key` | Function | `crates/agenc-ircd-crypto/src/storage.rs` | 252 |
| `new` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 27 |
| `seal` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 43 |
| `open` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 120 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 473 |
| `parse_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 195 |
| `validate_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 214 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 232 |
| `calculate_requested_backing_bytes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 241 |
| `parser_covers_empty_prefix_command_and_parameter_shapes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 325 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Run → Admit_len` | cross_community | 6 |
| `Seal → Put_fixed` | cross_community | 5 |
| `Open → Put_fixed` | cross_community | 5 |
| `Drive → Split_field` | cross_community | 5 |
| `Run → Split_field` | cross_community | 5 |
| `Run → Validate_key` | cross_community | 5 |
| `Run → Validate_correlation_value_len` | cross_community | 5 |
| `Run → Validate_decoded_value` | cross_community | 5 |
| `Rejects_changed_aad_and_tampering → Put_fixed` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 18 calls |
| Cluster_35 | 9 calls |
| Cluster_34 | 7 calls |
| Cluster_40 | 3 calls |
| Cluster_78 | 1 calls |
| Cluster_43 | 1 calls |
| Cluster_107 | 1 calls |
| Cluster_103 | 1 calls |

## How to Explore

1. `context({name: "as_str"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
