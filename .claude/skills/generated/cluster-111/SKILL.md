---
name: cluster-111
description: "Skill for the Cluster_111 area of agenc-ircd. 12 symbols across 1 files."
---

# Cluster_111

12 symbols | 1 files | Cohesion: 95%

## When to Use

- Working with code in `crates/`
- Understanding how parse, new, e2ee_tagmsg work
- Modifying cluster_111-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/command.rs` | parse, new, e2ee_tagmsg, channel, nickname (+7) |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-domain/src/command.rs:33`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/command.rs:181`
- **`e2ee_tagmsg`** (Function) — `crates/agenc-ircd-domain/src/command.rs:303`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-domain/src/command.rs` | 33 |
| `new` | Function | `crates/agenc-ircd-domain/src/command.rs` | 181 |
| `e2ee_tagmsg` | Function | `crates/agenc-ircd-domain/src/command.rs` | 303 |
| `channel` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1219 |
| `nickname` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1223 |
| `body` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1227 |
| `message_shapes_reject_counts_bodies_duplicates_and_mixed_authority` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1232 |
| `message_text_preserves_ctcp_action_and_irc_formatting_controls` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1316 |
| `plaintext_ctcp_dcc_is_rejected_without_blocking_other_ctcp` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1340 |
| `channel_target_commands_reject_limits_duplicates_and_mixed_authority` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1377 |
| `mode_and_kick_vectors_reject_limits_and_repeated_operations` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1433 |
| `query_and_monitor_constructors_enforce_protocol_bounds` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1660 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_113 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_111"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
