---
name: cluster-90
description: "Skill for the Cluster_90 area of agenc-ircd. 8 symbols across 1 files."
---

# Cluster_90

8 symbols | 1 files | Cohesion: 77%

## When to Use

- Working with code in `crates/`
- Understanding how bytes, account_id, session work
- Modifying cluster_90-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/projection.rs` | bytes, account_id, session, insert_session, account_and_session_projections_cover_hidden_public_and_contact_contexts (+3) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `bytes` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 447 |
| `account_id` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 451 |
| `session` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 455 |
| `insert_session` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 473 |
| `account_and_session_projections_cover_hidden_public_and_contact_contexts` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 484 |
| `channel_projection_and_member_buckets_fail_closed_at_every_boundary` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 587 |
| `session_context_and_topic_projection_cover_each_visibility_path` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 667 |
| `mutual_contact_guard_matrix_hides_every_incomplete_authority_chain` | Function | `crates/agenc-ircd-domain/src/projection.rs` | 777 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Session_context_and_topic_projection_cover_each_visibility_path → At_revision` | cross_community | 5 |
| `Channel_projection_and_member_buckets_fail_closed_at_every_boundary → At_revision` | cross_community | 5 |
| `Session_context_and_topic_projection_cover_each_visibility_path → Ascii_lowercase_copy` | cross_community | 4 |
| `Session_context_and_topic_projection_cover_each_visibility_path → Fallible_string_copy` | cross_community | 4 |
| `Channel_projection_and_member_buckets_fail_closed_at_every_boundary → Ascii_lowercase_copy` | cross_community | 4 |
| `Channel_projection_and_member_buckets_fail_closed_at_every_boundary → Fallible_string_copy` | cross_community | 4 |
| `Session_context_and_topic_projection_cover_each_visibility_path → From_random` | cross_community | 3 |
| `Session_context_and_topic_projection_cover_each_visibility_path → Bytes` | intra_community | 3 |
| `Session_context_and_topic_projection_cover_each_visibility_path → SessionSeed` | intra_community | 3 |
| `Session_context_and_topic_projection_cover_each_visibility_path → Len` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 9 calls |

## How to Explore

1. `context({name: "bytes"})` — see callers and callees
2. `query({search_query: "cluster_90"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
