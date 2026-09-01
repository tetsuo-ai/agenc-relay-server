---
name: cluster-209
description: "Skill for the Cluster_209 area of agenc-ircd. 38 symbols across 3 files."
---

# Cluster_209

38 symbols | 3 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how from_data, plan_account_created, plan_session_opened work
- Modifying cluster_209-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | insert, plan_account_created, plan_session_opened, plan_session_account_switch, resolve_switch_account (+31) |
| `crates/agenc-ircd-domain/src/command.rs` | from_data |
| `crates/agenc-ircd-types/src/identifiers.rs` | expose_for_deletion |

## Entry Points

Start here when exploring this area:

- **`from_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:1010`
- **`plan_account_created`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1257`
- **`plan_session_opened`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1272`
- **`plan_session_account_switch`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1287`
- **`plan_account_deleted`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1371`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `from_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1010 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1257 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1272 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1287 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1371 |
| `plan_account_deleted_at_revision` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1425 |
| `plan_account_credential_replaced` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1478 |
| `session_fanout_recipients` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1533 |
| `expose_for_deletion` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 168 |
| `insert` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 373 |
| `resolve_switch_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1342 |
| `add_invite_recipients` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1672 |
| `add_account_session_recipients` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1682 |
| `validate_session_seed` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1818 |
| `validate_account_deletion_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1855 |
| `plan_with_inputs` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2281 |
| `plan_nick` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2351 |
| `reserved_nickname_owner` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2378 |
| `plan_quit` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2387 |
| `plan_topic` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2700 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Admission | 27 calls |
| Cluster_226 | 1 calls |
| Tests | 1 calls |
| Cluster_224 | 1 calls |
| Cluster_203 | 1 calls |
| Cluster_225 | 1 calls |

## How to Explore

1. `context({name: "from_data"})` — see callers and callees
2. `query({search_query: "cluster_209"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
