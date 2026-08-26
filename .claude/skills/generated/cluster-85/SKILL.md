---
name: cluster-85
description: "Skill for the Cluster_85 area of agenc-ircd. 10 symbols across 1 files."
---

# Cluster_85

10 symbols | 1 files | Cohesion: 64%

## When to Use

- Working with code in `crates/`
- Understanding how new work
- Modifying cluster_85-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/client_transcript.rs` | new, render_action, render_non_capability_action, queue_capability_tokens, queue_capability (+5) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-testkit/src/client_transcript.rs:237`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 237 |
| `render_action` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 558 |
| `render_non_capability_action` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 589 |
| `queue_capability_tokens` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 660 |
| `queue_capability` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 679 |
| `queue_wire` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 791 |
| `recovery_epoch` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 811 |
| `copy_string` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 978 |
| `join_tokens` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 994 |
| `capability_trailing_budget` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 1014 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Drive → At` | cross_community | 6 |
| `Render_action → Command_bytes` | cross_community | 6 |
| `Render_action → Combined_tag_section` | cross_community | 6 |
| `Render_action → MeasuredMessage` | cross_community | 6 |
| `Render_non_capability_action → Escaped_len` | cross_community | 5 |
| `Queue_welcome_step → Command_bytes` | cross_community | 4 |
| `Queue_welcome_step → Combined_tag_section` | cross_community | 4 |
| `Queue_welcome_step → MeasuredMessage` | cross_community | 4 |
| `Render_non_capability_action → Command_bytes` | cross_community | 4 |
| `Render_non_capability_action → Combined_tag_section` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_30 | 2 calls |
| Fuzz_targets | 2 calls |
| Tests | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_85"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
