---
name: admin
description: "Skill for the Admin area of agenc-ircd. 102 symbols across 12 files."
---

# Admin

102 symbols | 12 files | Cohesion: 69%

## When to Use

- Working with code in `crates/`
- Understanding how verify, genesis, advance work
- Modifying admin-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin/audit.rs` | observe, finish_with_observed, new, select_expired_prefix, verify_export_coverage (+60) |
| `crates/agenc-ircd-runtime/src/admin.rs` | kill, mutate_account, mutate_channel, commit_mutation_with_stale_retry, mutation_revision (+11) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | build_live_state, persist_admin_policy_backfills, registration_config, start, test_observer (+1) |
| `crates/agenc-ircd-admin/src/audit.rs` | verify, genesis, advance, check_event_order |
| `crates/agenc-ircd-runtime/src/state_core/admin.rs` | target_revision, kill, commit_retention |
| `crates/agenc-ircd-admin/src/command.rs` | verb, contains |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | audit_signing_key_id |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | open |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | open_storage_plaintext |
| `crates/agenc-ircd-config/src/scalar.rs` | as_str |

## Entry Points

Start here when exploring this area:

- **`verify`** (Function) — `crates/agenc-ircd-admin/src/audit.rs:238`
- **`genesis`** (Function) — `crates/agenc-ircd-admin/src/audit.rs:456`
- **`advance`** (Function) — `crates/agenc-ircd-admin/src/audit.rs:473`
- **`audit_signing_key_id`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:346`
- **`finish_with_observed`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:497`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `verify` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 238 |
| `genesis` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 456 |
| `advance` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 473 |
| `audit_signing_key_id` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 346 |
| `finish_with_observed` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 497 |
| `verb` | Function | `crates/agenc-ircd-admin/src/command.rs` | 244 |
| `commit_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 401 |
| `target_revision` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 195 |
| `reconstruct` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 136 |
| `open` | Function | `crates/agenc-ircd-runtime/src/state_core/durable.rs` | 134 |
| `open_storage_plaintext` | Function | `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 580 |
| `as_str` | Function | `crates/agenc-ircd-config/src/scalar.rs` | 104 |
| `set_operational_limits` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1609 |
| `into_parts` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 95 |
| `policy_seed` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 281 |
| `contains` | Function | `crates/agenc-ircd-admin/src/command.rs` | 91 |
| `take_pending_startup_action` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 208 |
| `prepare_startup_outcome` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 217 |
| `resolve_committed_startup_action` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 262 |
| `kill` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 235 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → TrustedAuditKey` | intra_community | 4 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → Genesis` | intra_community | 4 |
| `Reconstruct → From_bytes` | cross_community | 3 |
| `Reconstruct → Tbs` | cross_community | 3 |
| `Reconstruct → Canonical_command` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 16 calls |
| Cluster_25 | 14 calls |
| State_core | 11 calls |
| Listener | 5 calls |
| Cluster_211 | 4 calls |
| Cluster_3 | 3 calls |
| Cluster_381 | 3 calls |
| Cluster_4 | 2 calls |

## How to Explore

1. `context({name: "verify"})` — see callers and callees
2. `query({search_query: "admin"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
