---
name: cluster-16
description: "Skill for the Cluster_16 area of agenc-ircd. 7 symbols across 2 files."
---

# Cluster_16

7 symbols | 2 files | Cohesion: 84%

## When to Use

- Working with code in `crates/`
- Understanding how actual_backing_capacities work
- Modifying cluster_16-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/message.rs` | from, maximal_message_stays_below_the_hard_parsed_arena, requested_allocation_charge, allocation_charge, maximal_parameter_section (+1) |
| `crates/agenc-ircd-client-wire/src/tags.rs` | actual_backing_capacities |

## Entry Points

Start here when exploring this area:

- **`actual_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:216`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `actual_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 216 |
| `from` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 147 |
| `maximal_message_stays_below_the_hard_parsed_arena` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 310 |
| `requested_allocation_charge` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 397 |
| `allocation_charge` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 415 |
| `maximal_parameter_section` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 424 |
| `maximal_two_byte_key_section` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 434 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Maximal_message_stays_below_the_hard_parsed_arena → Admit_len` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Split_field` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Validate_key` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → From` | intra_community | 3 |
| `Maximal_message_stays_below_the_hard_parsed_arena → As_str` | cross_community | 3 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Actual_backing_capacities` | intra_community | 3 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Allocation_charge` | intra_community | 3 |
| `Fmt → From` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Fuzz_targets | 1 calls |

## How to Explore

1. `context({name: "actual_backing_capacities"})` — see callers and callees
2. `query({search_query: "cluster_16"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
