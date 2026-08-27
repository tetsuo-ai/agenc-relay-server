---
name: cluster-33
description: "Skill for the Cluster_33 area of agenc-ircd. 17 symbols across 2 files."
---

# Cluster_33

17 symbols | 2 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how numeric_reply, new work
- Modifying cluster_33-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/client_transcript.rs` | new, render_action, render_non_capability_action, queue_capability_tokens, queue_capability (+9) |
| `crates/agenc-ircd-client-wire/src/render.rs` | numeric_reply, stage_two_numeric_shape_is_applicable, stage_two_numeric_middle_is_applicable |

## Entry Points

Start here when exploring this area:

- **`numeric_reply`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:725`
- **`new`** (Function) — `crates/agenc-ircd-testkit/src/client_transcript.rs:237`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `numeric_reply` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 725 |
| `new` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 237 |
| `stage_two_numeric_shape_is_applicable` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 757 |
| `stage_two_numeric_middle_is_applicable` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 769 |
| `render_action` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 558 |
| `render_non_capability_action` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 589 |
| `queue_capability_tokens` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 660 |
| `queue_capability` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 679 |
| `queue_welcome` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 718 |
| `queue_welcome_step` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 730 |
| `record_welcome_step` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 780 |
| `queue_wire` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 791 |
| `recovery_epoch` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 811 |
| `welcome_numerics` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 822 |
| `copy_string` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 978 |
| `join_tokens` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 994 |
| `capability_trailing_budget` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 1014 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Drive → At` | cross_community | 6 |
| `Queue_welcome_step → Command_bytes` | cross_community | 4 |
| `Queue_welcome_step → Combined_tag_section` | cross_community | 4 |
| `Queue_welcome_step → MeasuredMessage` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Fuzz_targets | 2 calls |
| Cluster_25 | 2 calls |
| Tests | 1 calls |
| Cluster_27 | 1 calls |

## How to Explore

1. `context({name: "numeric_reply"})` — see callers and callees
2. `query({search_query: "cluster_33"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
