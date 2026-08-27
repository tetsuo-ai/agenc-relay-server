---
name: cluster-12
description: "Skill for the Cluster_12 area of agenc-ircd. 10 symbols across 2 files."
---

# Cluster_12

10 symbols | 2 files | Cohesion: 93%

## When to Use

- Working with code in `crates/`
- Understanding how feed, finish, timeout work
- Modifying cluster_12-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/framing.rs` | feed, finish, timeout, accept_byte, push_content (+4) |
| `crates/agenc-ircd-testkit/src/client_transcript.rs` | finish |

## Entry Points

Start here when exploring this area:

- **`feed`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:116`
- **`finish`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:129`
- **`timeout`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:138`
- **`finish`** (Function) — `crates/agenc-ircd-testkit/src/client_transcript.rs:323`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `feed` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 116 |
| `finish` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 129 |
| `timeout` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 138 |
| `finish` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 323 |
| `accept_byte` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 146 |
| `push_content` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 171 |
| `emit_line` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 198 |
| `fail` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 219 |
| `clear` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 224 |
| `drop` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 268 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Feed → Clear` | intra_community | 5 |
| `Feed → Validate_line_budgets` | cross_community | 4 |
| `Feed → At` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 1 calls |
| Cluster_10 | 1 calls |

## How to Explore

1. `context({name: "feed"})` — see callers and callees
2. `query({search_query: "cluster_12"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
