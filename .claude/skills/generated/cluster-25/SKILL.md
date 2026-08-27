---
name: cluster-25
description: "Skill for the Cluster_25 area of agenc-ircd. 9 symbols across 1 files."
---

# Cluster_25

9 symbols | 1 files | Cohesion: 58%

## When to Use

- Working with code in `crates/`
- Understanding how encode, isupport_messages work
- Modifying cluster_25-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/render.rs` | new, encode, reply_context_text, encode_public_identifier, decimal_text (+4) |

## Entry Points

Start here when exploring this area:

- **`encode`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:369`
- **`isupport_messages`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:816`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `encode` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 369 |
| `isupport_messages` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 816 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 107 |
| `reply_context_text` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 680 |
| `encode_public_identifier` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 702 |
| `decimal_text` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 712 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1332 |
| `copy_strings` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1341 |
| `prefixed_value` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1352 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Add_client_only_tag → Validate_parameter_count` | cross_community | 6 |
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Add_client_only_tag → Validate_prefix` | cross_community | 6 |
| `Add_client_only_tag → Validate_command` | cross_community | 6 |
| `Labeled_response → Validate_parameter_count` | cross_community | 6 |
| `Labeled_response → Command_bytes` | cross_community | 6 |
| `Labeled_response → Validate_prefix` | cross_community | 6 |
| `Labeled_response → Validate_command` | cross_community | 6 |
| `Slow_consumer_warning → Validate_parameter_count` | cross_community | 5 |
| `Slow_consumer_warning → Command_bytes` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_28 | 1 calls |
| Cluster_27 | 1 calls |
| Cluster_33 | 1 calls |

## How to Explore

1. `context({name: "encode"})` — see callers and callees
2. `query({search_query: "cluster_25"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
