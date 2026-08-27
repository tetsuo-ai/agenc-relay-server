---
name: cluster-13
description: "Skill for the Cluster_13 area of agenc-ircd. 8 symbols across 2 files."
---

# Cluster_13

8 symbols | 2 files | Cohesion: 84%

## When to Use

- Working with code in `crates/`
- Understanding how relays_client_only_tags, add_server_tag, add_client_only_tag work
- Modifying cluster_13-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/render.rs` | add_server_tag, add_client_only_tag, insert_tag, validate_client_tag_budget, tag_data_bytes_with (+2) |
| `crates/agenc-ircd-client-wire/src/limits.rs` | relays_client_only_tags |

## Entry Points

Start here when exploring this area:

- **`relays_client_only_tags`** (Function) — `crates/agenc-ircd-client-wire/src/limits.rs:31`
- **`add_server_tag`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:246`
- **`add_client_only_tag`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:254`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `relays_client_only_tags` | Function | `crates/agenc-ircd-client-wire/src/limits.rs` | 31 |
| `add_server_tag` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 246 |
| `add_client_only_tag` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 254 |
| `insert_tag` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1108 |
| `validate_client_tag_budget` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1149 |
| `tag_data_bytes_with` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1176 |
| `tag_data_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1194 |
| `escaped_len` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1223 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Escaped_len` | cross_community | 7 |
| `Add_client_only_tag → Validate_parameter_count` | cross_community | 6 |
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Add_client_only_tag → Validate_prefix` | cross_community | 6 |
| `Add_client_only_tag → Validate_command` | cross_community | 6 |
| `Add_client_only_tag → Escaped_len` | intra_community | 5 |
| `Labeled_response → RenderTag` | cross_community | 5 |
| `Render_non_capability_action → Escaped_len` | cross_community | 5 |
| `Add_client_only_tag → RenderTag` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_24 | 1 calls |

## How to Explore

1. `context({name: "relays_client_only_tags"})` — see callers and callees
2. `query({search_query: "cluster_13"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
