---
name: cluster-58
description: "Skill for the Cluster_58 area of agenc-ircd. 13 symbols across 1 files."
---

# Cluster_58

13 symbols | 1 files | Cohesion: 67%

## When to Use

- Working with code in `crates/`
- Understanding how encode, isupport_messages work
- Modifying cluster_58-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/render.rs` | new, new_registered, encode, reply_context_text, encode_public_identifier (+8) |

## Entry Points

Start here when exploring this area:

- **`encode`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:369`
- **`isupport_messages`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:819`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `encode` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 369 |
| `isupport_messages` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 819 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 107 |
| `new_registered` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 193 |
| `reply_context_text` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 683 |
| `encode_public_identifier` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 705 |
| `decimal_text` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 715 |
| `validate_command` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1054 |
| `validate_parameters` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1066 |
| `validate_parameter_count` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1106 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1353 |
| `copy_strings` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1362 |
| `prefixed_value` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1373 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Validate_parameter_count` | cross_community | 8 |
| `Labeled_response → Command_bytes` | cross_community | 8 |
| `Labeled_response → Validate_prefix` | cross_community | 8 |
| `Labeled_response → Validate_command` | cross_community | 7 |
| `Add_client_only_tag → Validate_parameter_count` | cross_community | 6 |
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Add_client_only_tag → Validate_prefix` | cross_community | 6 |
| `Add_client_only_tag → Validate_command` | cross_community | 6 |
| `Slow_consumer_warning → Validate_parameter_count` | cross_community | 5 |
| `Slow_consumer_warning → Command_bytes` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Fuzz_targets | 1 calls |
| Cluster_60 | 1 calls |
| Cluster_65 | 1 calls |

## How to Explore

1. `context({name: "encode"})` — see callers and callees
2. `query({search_query: "cluster_58"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
