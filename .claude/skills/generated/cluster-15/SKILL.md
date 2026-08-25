---
name: cluster-15
description: "Skill for the Cluster_15 area of agenc-ircd. 6 symbols across 1 files."
---

# Cluster_15

6 symbols | 1 files | Cohesion: 91%

## When to Use

- Working with code in `crates/`
- Understanding how discriminated_arm, projection_arm, directory_arm work
- Modifying cluster_15-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | discriminated_arm, projection_arm, directory_arm, operation_arm, result_arm (+1) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `discriminated_arm` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 302 |
| `projection_arm` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1515 |
| `directory_arm` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1526 |
| `operation_arm` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1548 |
| `result_arm` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1579 |
| `event_arm` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1593 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Process_walk_frame → Directory_arm` | cross_community | 6 |
| `Process_walk_frame → Event_arm` | cross_community | 6 |
| `Process_object_walk → Projection_arm` | cross_community | 5 |
| `Process_object_walk → Operation_arm` | cross_community | 5 |

## How to Explore

1. `context({name: "discriminated_arm"})` — see callers and callees
2. `query({search_query: "cluster_15"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
