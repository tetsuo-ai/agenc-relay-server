---
name: cluster-35
description: "Skill for the Cluster_35 area of agenc-ircd. 8 symbols across 1 files."
---

# Cluster_35

8 symbols | 1 files | Cohesion: 64%

## When to Use

- Working with code in `crates/`
- Understanding how validate_tag_section, admit, admit_len work
- Modifying cluster_35-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/tags.rs` | validate_tag_section, admit, admit_len, validate_rendered_collection, reject_duplicate_source_keys (+3) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_tag_section` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 426 |
| `admit` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 471 |
| `admit_len` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 475 |
| `validate_rendered_collection` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 531 |
| `reject_duplicate_source_keys` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 566 |
| `validate_key` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 586 |
| `validate_correlation_value` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 597 |
| `validate_correlation_value_len` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 601 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Drive → Admit_len` | cross_community | 6 |
| `Run → At` | cross_community | 6 |
| `Run → Admit_len` | cross_community | 5 |
| `Run → Split_field` | cross_community | 5 |
| `Run → Validate_key` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Admit_len` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Split_field` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Validate_key` | cross_community | 5 |
| `Exercise_registration → Admit_len` | cross_community | 5 |
| `Drive_client → Split_field` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |
| Cluster_31 | 2 calls |

## How to Explore

1. `context({name: "validate_tag_section"})` — see callers and callees
2. `query({search_query: "cluster_35"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
