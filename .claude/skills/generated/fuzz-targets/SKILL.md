---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 65 symbols across 8 files."
---

# Fuzz_targets

65 symbols | 8 files | Cohesion: 66%

## When to Use

- Working with code in `fuzz/`
- Understanding how new, try_clone, apply_profile work
- Modifying fuzz_targets-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `fuzz/fuzz_targets/client_state.rs` | exercise_capability_changes, exercise_post_registration_line, exercise_decimal_and_base64, exercise_capability_ls, exercise_capability_line_splitting (+12) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | new, try_clone, ls_token, apply_profile, diff_advertisements (+10) |
| `fuzz/fuzz_targets/parse_render.rs` | new, exercise_boundary_render_plan, exercise_exact_render_boundaries, render_prefix, render_middle (+6) |
| `crates/agenc-ircd-runtime/src/command_convert.rs` | convert, every_state_independent_public_family_converts_to_its_domain_kind, channel_mode_list_and_multi_change_remain_distinct, channel_key_modes_enforce_secret_bounds_and_track_each_parameter, converted (+2) |
| `crates/agenc-ircd-client-wire/src/text.rs` | parse_u16_decimal, parse_u32_decimal, parse_u64_decimal, parse_decimal, parse_fragment_decimal (+1) |
| `fuzz/fuzz_targets/websocket.rs` | exercise_fragmented_sequence, assert_control_event, exercise_arbitrary_frame, exercise_oversized_message, data_opcode (+1) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_local_information |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:35`
- **`try_clone`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:78`
- **`apply_profile`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:369`
- **`measure`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:374`
- **`validate_post_registration_command`** (Function) — `crates/agenc-ircd-client-wire/src/registration_command.rs:406`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 35 |
| `try_clone` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 78 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 369 |
| `measure` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 374 |
| `validate_post_registration_command` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 406 |
| `convert` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 19 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 473 |
| `ls_token` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 85 |
| `diff_advertisements` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 438 |
| `apply_requested_tokens` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 520 |
| `insert_unique` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 596 |
| `reconnects_on_value_change` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 628 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 665 |
| `copy_strings` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 674 |
| `copy_specs` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 685 |
| `profile_does_not_retain_caller_vector_headroom` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 709 |
| `capability_state_covers_atomic_negotiation_and_profile_changes` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 758 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Apply_action → CapLine` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Validate_ | 14 calls |
| Tests | 13 calls |
| State_core | 4 calls |
| Coordinator | 3 calls |
| Cluster_77 | 2 calls |
| Cluster_250 | 2 calls |
| Cluster_79 | 2 calls |
| Cluster_128 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
