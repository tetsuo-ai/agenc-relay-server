---
name: cluster-63
description: "Skill for the Cluster_63 area of agenc-ircd. 18 symbols across 2 files."
---

# Cluster_63

18 symbols | 2 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how numeric_reply, new work
- Modifying cluster_63-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/client_transcript.rs` | new, render_action, render_non_capability_action, queue_capability_tokens, queue_capability (+10) |
| `crates/agenc-ircd-client-wire/src/render.rs` | numeric_reply, stage_two_numeric_shape_is_applicable, stage_two_numeric_middle_is_applicable |

## Entry Points

Start here when exploring this area:

- **`numeric_reply`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:728`
- **`new`** (Function) — `crates/agenc-ircd-testkit/src/client_transcript.rs:237`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `numeric_reply` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 728 |
| `new` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 237 |
| `stage_two_numeric_shape_is_applicable` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 760 |
| `stage_two_numeric_middle_is_applicable` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 772 |
| `render_action` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 558 |
| `render_non_capability_action` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 589 |
| `queue_capability_tokens` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 660 |
| `queue_capability` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 680 |
| `queue_welcome` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 719 |
| `queue_welcome_step` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 731 |
| `record_welcome_step` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 781 |
| `queue_wire` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 792 |
| `recovery_epoch` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 812 |
| `welcome_numerics` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 823 |
| `copy_string` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 979 |
| `join_tokens` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 995 |
| `capability_trailing_budget` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 1015 |
| `cap_302_list_uses_bounded_continuation_lines` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 1037 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Drive → At` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_57 | 3 calls |
| Fuzz_targets | 2 calls |
| Tests | 1 calls |

## How to Explore

1. `context({name: "numeric_reply"})` — see callers and callees
2. `query({search_query: "cluster_63"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
