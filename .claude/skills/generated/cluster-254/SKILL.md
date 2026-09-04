---
name: cluster-254
description: "Skill for the Cluster_254 area of agenc-ircd. 117 symbols across 3 files."
---

# Cluster_254

117 symbols | 3 files | Cohesion: 94%

## When to Use

- Working with code in `crates/`
- Understanding how new, user, plan_account_service_checkpoint work
- Modifying cluster_254-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, user, message, collect (+105) |
| `crates/agenc-ircd-domain/src/model.rs` | principal, joined, new_ephemeral, role_of, admin_restore_account (+1) |
| `crates/agenc-ircd-types/src/quantities.rs` | from_ticks |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:63`
- **`user`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:515`
- **`plan_account_service_checkpoint`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1510`
- **`plan_account_created`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1523`
- **`plan_session_opened`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1538`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 63 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 515 |
| `plan_account_service_checkpoint` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1510 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1523 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1538 |
| `plan_session_disconnected` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1554 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1569 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1653 |
| `plan_account_deleted_at_revision` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1707 |
| `plan_session_fresh_authentication` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1724 |
| `plan_account_credential_replaced` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1760 |
| `plan_e2ee_binding` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1820 |
| `plan_e2ee_removal_finalized` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1868 |
| `plan_expired_invites` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1900 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2057 |
| `principal` | Function | `crates/agenc-ircd-domain/src/model.rs` | 807 |
| `joined` | Function | `crates/agenc-ircd-domain/src/model.rs` | 935 |
| `new_ephemeral` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1128 |
| `role_of` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1266 |
| `admin_restore_account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1737 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 22 calls |
| Coordinator | 10 calls |
| Cluster_275 | 6 calls |
| State_core | 5 calls |
| Cluster_269 | 2 calls |
| Cluster_261 | 2 calls |
| Cluster_331 | 1 calls |
| Cluster_325 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_254"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
