---
name: cluster-238
description: "Skill for the Cluster_238 area of agenc-ircd. 18 symbols across 1 files."
---

# Cluster_238

18 symbols | 1 files | Cohesion: 85%

## When to Use

- Working with code in `crates/`
- Understanding how start, shutdown work
- Modifying cluster_238-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/owner.rs` | start, shutdown, join_owner, drop, new (+13) |

## Entry Points

Start here when exploring this area:

- **`start`** (Function) — `crates/agenc-ircd-storage/src/owner.rs:123`
- **`shutdown`** (Function) — `crates/agenc-ircd-storage/src/owner.rs:178`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `start` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 123 |
| `shutdown` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 178 |
| `join_owner` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 182 |
| `drop` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 211 |
| `new` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 226 |
| `run_owner` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 241 |
| `read_request` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 456 |
| `commit_request` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 462 |
| `queue` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 467 |
| `take` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 474 |
| `commit_first_account` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 478 |
| `drive_checkpoint` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 487 |
| `due_checkpoint_starts_before_queued_requests_and_interleaves_them` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 502 |
| `rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 534 |
| `backup_queued_beside_a_checkpoint_is_deferred_until_the_checkpoint_installs` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 610 |
| `indeterminate_checkpoint_installation_stops_the_owner` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 669 |
| `completion_distinguishes_pending_success_failure_and_disconnect` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 699 |
| `submission_and_checkpoint_errors_preserve_failure_classification` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 724 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Tbs` | cross_community | 6 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Expected_storage_commit_sequence` | cross_community | 6 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Expected_state_generation` | cross_community | 6 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Expected_account_service_response_count` | cross_community | 6 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Fault_site` | cross_community | 5 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Faults` | cross_community | 5 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Check` | cross_community | 5 |
| `Start → Validate_file` | cross_community | 5 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → New` | cross_community | 4 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Secret_bytes` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 2 calls |
| Cluster_221 | 2 calls |
| Cluster_216 | 2 calls |
| Cluster_193 | 1 calls |
| Cluster_211 | 1 calls |
| Cluster_220 | 1 calls |
| Cluster_224 | 1 calls |

## How to Explore

1. `context({name: "start"})` — see callers and callees
2. `query({search_query: "cluster_238"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
