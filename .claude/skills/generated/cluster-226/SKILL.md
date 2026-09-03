---
name: cluster-226
description: "Skill for the Cluster_226 area of agenc-ircd. 112 symbols across 4 files."
---

# Cluster_226

112 symbols | 4 files | Cohesion: 80%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, into_parts, new work
- Modifying cluster_226-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, is_empty, user, message (+98) |
| `crates/agenc-ircd-domain/src/model.rs` | principal, joined, new_ephemeral, role_of, at_revision (+1) |
| `crates/agenc-ircd-domain/src/command.rs` | into_name, into_parts |
| `crates/agenc-ircd-types/src/identifiers.rs` | expose_for_deletion |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:197`
- **`into_parts`** (Function) — `crates/agenc-ircd-domain/src/command.rs:339`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:63`
- **`is_empty`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:401`
- **`user`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:515`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 197 |
| `into_parts` | Function | `crates/agenc-ircd-domain/src/command.rs` | 339 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 63 |
| `is_empty` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 401 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 515 |
| `plan_account_service_checkpoint` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1510 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1523 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1538 |
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

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 30 calls |
| State_core | 11 calls |
| Admission | 8 calls |
| Cluster_232 | 7 calls |
| Cluster_296 | 5 calls |
| Cluster_252 | 2 calls |
| Cluster_241 | 2 calls |
| Cluster_36 | 2 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "cluster_226"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
