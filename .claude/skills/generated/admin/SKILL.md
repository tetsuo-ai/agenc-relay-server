---
name: admin
description: "Skill for the Admin area of agenc-ircd. 79 symbols across 7 files."
---

# Admin

79 symbols | 7 files | Cohesion: 62%

## When to Use

- Working with code in `crates/`
- Understanding how genesis, advance, audit_signing_key_id work
- Modifying admin-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin/audit.rs` | new, verify_checkpoints, verify_events, binding, registry (+54) |
| `crates/agenc-ircd-runtime/src/admin.rs` | issue_confirmation, prepare_rehash_outcomes, prepare_observed_event, commit_observed, output_storage_unavailable (+6) |
| `crates/agenc-ircd-admin/src/audit.rs` | genesis, advance, check_event_order, verify |
| `crates/agenc-ircd-admin/src/command.rs` | contains, verb |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | audit_signing_key_id |
| `crates/agenc-ircd-runtime/src/state_core/admin.rs` | target_revision |
| `crates/agenc-ircd-runtime/src/cancel.rs` | is_cancelled |

## Entry Points

Start here when exploring this area:

- **`genesis`** (Function) — `crates/agenc-ircd-admin/src/audit.rs:456`
- **`advance`** (Function) — `crates/agenc-ircd-admin/src/audit.rs:473`
- **`audit_signing_key_id`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:367`
- **`reconstruct`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:136`
- **`contains`** (Function) — `crates/agenc-ircd-admin/src/command.rs:91`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `genesis` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 456 |
| `advance` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 473 |
| `audit_signing_key_id` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 367 |
| `reconstruct` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 136 |
| `contains` | Function | `crates/agenc-ircd-admin/src/command.rs` | 91 |
| `verb` | Function | `crates/agenc-ircd-admin/src/command.rs` | 244 |
| `prepare_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 367 |
| `verify` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 238 |
| `commit_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 401 |
| `target_revision` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 205 |
| `take_pending_startup_action` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 208 |
| `prepare_startup_outcome` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 217 |
| `resolve_committed_startup_action` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 262 |
| `prepare_retention` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 304 |
| `is_cancelled` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 75 |
| `is_reconciled` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 192 |
| `prepare_export` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 285 |
| `commit_retention` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 343 |
| `finish_with_observed` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 497 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 681 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Federation_commands_record_intent_and_outcome → Verb` | cross_community | 5 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → TrustedAuditKey` | intra_community | 4 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → Genesis` | intra_community | 4 |
| `Reconstruct → From_bytes` | cross_community | 3 |
| `Reconstruct → Tbs` | cross_community | 3 |
| `Reconstruct → Canonical_command` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 12 calls |
| Cluster_489 | 11 calls |
| Cluster_488 | 5 calls |
| Coordinator | 5 calls |
| State_core | 4 calls |
| Examples | 4 calls |
| Cluster_3 | 2 calls |
| Cluster_4 | 2 calls |

## How to Explore

1. `context({name: "genesis"})` — see callers and callees
2. `query({search_query: "admin"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
