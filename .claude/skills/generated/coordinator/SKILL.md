---
name: coordinator
description: "Skill for the Coordinator area of agenc-ircd. 308 symbols across 64 files."
---

# Coordinator

308 symbols | 64 files | Cohesion: 50%

## When to Use

- Working with code in `crates/`
- Understanding how as_bytes, tracked_record_commitment, tracked_state_digest work
- Modifying coordinator-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/e2ee_records.rs` | encode, encoder, put_bool, put_optional_hash, put_hashes (+26) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/sync.rs` | begin_snapshot, entitled_entries, state_fetch, render_page, snapshot_write (+18) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | run_operation, run_query, answer_page, finish_query_decision, open_session (+17) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/mod.rs` | start_companion, companion_timer_fired, fail_link, timer_fired, link_established (+17) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/snapshot.rs` | build_cut, timer_fired, expire, open_generation, continue_write (+13) |
| `crates/agenc-ircd-storage/src/domain_records.rs` | encode, put_optional_account_id, encode_version, put_optional_text, put_optional_second (+11) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | channel_name, reason, rebuild_command, message_command, account_command (+10) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/companion.rs` | snapshot_timer_fired, base_ready, send_lines, send_to_target, request_committed (+8) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/query.rs` | expire, new, next_page, binding, expired_page (+7) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/request.rs` | kind, encode, encode_result, optional, descriptor (+6) |

## Entry Points

Start here when exploring this area:

- **`as_bytes`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:120`
- **`tracked_record_commitment`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:295`
- **`tracked_state_digest`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:300`
- **`update`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:336`
- **`finalize`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:349`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_bytes` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 120 |
| `tracked_record_commitment` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 295 |
| `tracked_state_digest` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 300 |
| `update` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 336 |
| `finalize` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 349 |
| `offset` | Function | `crates/agenc-ircd-e2ee/src/wire/fragment.rs` | 117 |
| `snapshot_digest` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 98 |
| `required_reserve` | Function | `crates/agenc-ircd-runtime/src/admission/overload.rs` | 133 |
| `state_fetch` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/sync.rs` | 644 |
| `snapshot_end` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 223 |
| `with_capacity` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 10 |
| `put_u16` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 21 |
| `put_u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 25 |
| `put_u64` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 29 |
| `put_fixed` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 33 |
| `put_vector_u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 46 |
| `encode` | Function | `crates/agenc-ircd-storage/src/domain_records.rs` | 143 |
| `encode` | Function | `crates/agenc-ircd-storage/src/e2ee_records.rs` | 277 |
| `contributed_bytes` | Function | `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | 346 |
| `compute_tracked_state_digest` | Function | `crates/agenc-ircd-storage/src/integrity.rs` | 560 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Route_sasl → Try_from` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Preview → Try_from` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Serve → Try_from` | cross_community | 6 |
| `Origin_state → Take` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Put_fixed` | cross_community | 6 |
| `Run → Try_from` | cross_community | 5 |
| `Batch_applied → Link_is_live` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 65 calls |
| State_core | 41 calls |
| Federation | 15 calls |
| Ops | 15 calls |
| E2ee_records | 14 calls |
| Codec | 9 calls |
| Cluster_797 | 4 calls |
| Cluster_795 | 3 calls |

## How to Explore

1. `context({name: "as_bytes"})` — see callers and callees
2. `query({search_query: "coordinator"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
