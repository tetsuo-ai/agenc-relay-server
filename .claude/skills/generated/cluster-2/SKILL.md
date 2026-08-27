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

- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:36`
- **`request`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:270`
- **`apply_profile`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:364`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 36 |
| `request` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 270 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 364 |
| `ls_token` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 86 |
| `contains` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 138 |
| `prepare_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 418 |
| `diff_advertisements` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 433 |
| `apply_requested_tokens` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 515 |
| `validate_dependencies` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 543 |
| `ensure_token_list_renderable` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 554 |
| `dependencies` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 566 |
| `insert_unique` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 584 |
| `reconnects_on_value_change` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 616 |
| `validate_advertisement` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 630 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 653 |
| `copy_strings` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 662 |
| `copy_specs` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 673 |
| `profile_does_not_retain_caller_vector_headroom` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 697 |
| `capability_values_reject_each_malformed_shape` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 710 |

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
