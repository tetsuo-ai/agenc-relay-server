---
name: cluster-30
description: "Skill for the Cluster_30 area of agenc-ircd. 10 symbols across 2 files."
---

# Cluster_30

10 symbols | 2 files | Cohesion: 65%

## When to Use

- Working with code in `crates/`
- Understanding how numeric_reply, isupport_messages work
- Modifying cluster_30-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/render.rs` | encode_public_identifier, numeric_reply, stage_two_numeric_shape_is_applicable, stage_two_numeric_middle_is_applicable, isupport_messages (+1) |
| `crates/agenc-ircd-testkit/src/client_transcript.rs` | queue_welcome, queue_welcome_step, record_welcome_step, welcome_numerics |

## Entry Points

Start here when exploring this area:

- **`numeric_reply`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:714`
- **`isupport_messages`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:805`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `numeric_reply` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 714 |
| `isupport_messages` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 805 |
| `encode_public_identifier` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 691 |
| `stage_two_numeric_shape_is_applicable` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 746 |
| `stage_two_numeric_middle_is_applicable` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 758 |
| `prefixed_value` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1341 |
| `queue_welcome` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 718 |
| `queue_welcome_step` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 730 |
| `record_welcome_step` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 780 |
| `welcome_numerics` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 822 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Validate_parameter_count` | cross_community | 6 |
| `Labeled_response → Command_bytes` | cross_community | 6 |
| `Labeled_response → Validate_prefix` | cross_community | 6 |
| `Labeled_response → Validate_command` | cross_community | 6 |
| `Queue_welcome_step → Command_bytes` | cross_community | 4 |
| `Queue_welcome_step → Combined_tag_section` | cross_community | 4 |
| `Queue_welcome_step → MeasuredMessage` | cross_community | 4 |
| `Isupport_messages → Validate_command` | cross_community | 4 |
| `Isupport_messages → Validate_parameter_count` | cross_community | 4 |
| `Isupport_messages → Command_bytes` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_85 | 7 calls |
| Tests | 3 calls |
| Cluster_24 | 1 calls |

## How to Explore

1. `context({name: "numeric_reply"})` — see callers and callees
2. `query({search_query: "cluster_30"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
