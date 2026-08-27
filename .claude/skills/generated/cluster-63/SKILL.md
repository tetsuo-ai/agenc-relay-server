---
name: cluster-63
description: "Skill for the Cluster_63 area of agenc-ircd. 11 symbols across 1 files."
---

# Cluster_63

11 symbols | 1 files | Cohesion: 100%

## When to Use

- Working with code in `crates/`
- Understanding how new work
- Modifying cluster_63-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/command.rs` | new, validate_message_shape, validate_message_targets, same_message_target, is_local_message_target (+6) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-domain/src/command.rs:144`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-domain/src/command.rs` | 144 |
| `validate_message_shape` | Function | `crates/agenc-ircd-domain/src/command.rs` | 231 |
| `validate_message_targets` | Function | `crates/agenc-ircd-domain/src/command.rs` | 255 |
| `same_message_target` | Function | `crates/agenc-ircd-domain/src/command.rs` | 277 |
| `is_local_message_target` | Function | `crates/agenc-ircd-domain/src/command.rs` | 294 |
| `channel` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1059 |
| `nickname` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1063 |
| `message_shapes_reject_counts_bodies_duplicates_and_mixed_authority` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1072 |
| `channel_target_commands_reject_limits_duplicates_and_mixed_authority` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1156 |
| `mode_and_kick_vectors_reject_limits_and_repeated_operations` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1212 |
| `query_and_monitor_constructors_enforce_protocol_bounds` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1416 |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_63"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
