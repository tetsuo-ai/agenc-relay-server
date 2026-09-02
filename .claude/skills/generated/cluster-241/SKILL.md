---
name: cluster-241
description: "Skill for the Cluster_241 area of agenc-ircd. 36 symbols across 2 files."
---

# Cluster_241

36 symbols | 2 files | Cohesion: 87%

## When to Use

- Working with code in `crates/`
- Understanding how user_mode_query, kick, user_query work
- Modifying cluster_241-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/command_convert.rs` | convert_public, nickname, join, part, mode_query (+26) |
| `crates/agenc-ircd-domain/src/command.rs` | user_mode_query, kick, user_query, validate_nickname_targets, has_duplicate_nicknames |

## Entry Points

Start here when exploring this area:

- **`user_mode_query`** (Function) — `crates/agenc-ircd-domain/src/command.rs:783`
- **`kick`** (Function) — `crates/agenc-ircd-domain/src/command.rs:842`
- **`user_query`** (Function) — `crates/agenc-ircd-domain/src/command.rs:870`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `user_mode_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 783 |
| `kick` | Function | `crates/agenc-ircd-domain/src/command.rs` | 842 |
| `user_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 870 |
| `validate_nickname_targets` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1046 |
| `has_duplicate_nicknames` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1154 |
| `convert_public` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 31 |
| `nickname` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 77 |
| `join` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 84 |
| `part` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 98 |
| `mode_query` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 109 |
| `mode_change` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 120 |
| `user_mode_change` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 131 |
| `topic_query` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 327 |
| `topic_set` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 333 |
| `names` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 343 |
| `list` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 349 |
| `invite` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 353 |
| `kick` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 365 |
| `message_command` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 378 |
| `who` | Function | `crates/agenc-ircd-runtime/src/command_convert.rs` | 405 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 12 calls |
| Cluster_242 | 1 calls |

## How to Explore

1. `context({name: "user_mode_query"})` — see callers and callees
2. `query({search_query: "cluster_241"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
