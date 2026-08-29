---
name: cluster-79
description: "Skill for the Cluster_79 area of agenc-ircd. 14 symbols across 1 files."
---

# Cluster_79

14 symbols | 1 files | Cohesion: 87%

## When to Use

- Working with code in `crates/`
- Understanding how new work
- Modifying cluster_79-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/websocket.rs` | protocol, invalid_utf8, too_large, internal, new (+9) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/websocket.rs:175`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 175 |
| `protocol` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 128 |
| `invalid_utf8` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 135 |
| `too_large` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 142 |
| `internal` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 149 |
| `accept_data` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 206 |
| `continue_message` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 239 |
| `append_fragment` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 267 |
| `matches_subprotocol` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 316 |
| `unmask_bounded` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 350 |
| `validate_message` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 372 |
| `map_framing_error` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 388 |
| `parse_close` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 401 |
| `valid_close_code` | Function | `crates/agenc-ircd-client-wire/src/websocket.rs` | 443 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_78 | 8 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_79"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
