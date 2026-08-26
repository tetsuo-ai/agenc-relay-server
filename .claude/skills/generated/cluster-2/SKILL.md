---
name: cluster-2
description: "Skill for the Cluster_2 area of agenc-ircd. 19 symbols across 1 files."
---

# Cluster_2

19 symbols | 1 files | Cohesion: 74%

## When to Use

- Working with code in `crates/`
- Understanding how new, request, apply_profile work
- Modifying cluster_2-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/capability.rs` | new, ls_token, contains, request, apply_profile (+14) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:34`
- **`request`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:268`
- **`apply_profile`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:361`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 34 |
| `request` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 268 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 361 |
| `ls_token` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 84 |
| `contains` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 136 |
| `prepare_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 415 |
| `diff_advertisements` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 430 |
| `apply_requested_tokens` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 512 |
| `validate_dependencies` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 540 |
| `ensure_token_list_renderable` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 551 |
| `dependencies` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 563 |
| `insert_unique` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 581 |
| `reconnects_on_value_change` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 613 |
| `validate_advertisement` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 627 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 650 |
| `copy_strings` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 659 |
| `copy_specs` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 670 |
| `profile_does_not_retain_caller_vector_headroom` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 694 |
| `capability_values_reject_each_malformed_shape` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 707 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Capability_state_covers_atomic_negotiation_and_profile_changes → Copy_string` | cross_community | 5 |
| `Capability_state_covers_atomic_negotiation_and_profile_changes → CapabilitySpec` | cross_community | 5 |
| `Exercise_capability_state → Capabilities` | cross_community | 5 |
| `Exercise_capability_state → Ensure_token_list_renderable` | cross_community | 5 |
| `Exercise_capability_state → Copy_string` | cross_community | 5 |
| `Message_tag_capabilities → CapabilitySpec` | cross_community | 5 |
| `Message_tag_capabilities → Copy_string` | cross_community | 5 |
| `Message_tag_capabilities → Dependencies` | cross_community | 5 |
| `Capability_state_covers_atomic_negotiation_and_profile_changes → Capabilities` | cross_community | 4 |
| `Negotiating_message → Ensure_token_list_renderable` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_9 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_2"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
