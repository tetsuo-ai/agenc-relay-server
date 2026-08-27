---
name: cluster-79
description: "Skill for the Cluster_79 area of agenc-ircd. 11 symbols across 1 files."
---

# Cluster_79

11 symbols | 1 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how accept work
- Modifying cluster_79-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/websocket.rs` | drop, protocol, accept, accept_data, continue_message (+6) |

## Entry Points

Start here when exploring this area:

- **`accept`** (Function) — `crates/agenc-ircd-client-wire/src/websocket.rs:189`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `accept` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 189 |
| `drop` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 103 |
| `protocol` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 128 |
| `accept_data` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 206 |
| `continue_message` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 239 |
| `append_fragment` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 267 |
| `accept_control` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 286 |
| `matches_subprotocol` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 316 |
| `fail` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 324 |
| `clear_message` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 330 |
| `is_control` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 343 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_80 | 8 calls |

## How to Explore

1. `context({name: "accept"})` — see callers and callees
2. `query({search_query: "cluster_79"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
