---
name: cluster-84
description: "Skill for the Cluster_84 area of agenc-ircd. 47 symbols across 3 files."
---

# Cluster_84

47 symbols | 3 files | Cohesion: 80%

## When to Use

- Working with code in `crates/`
- Understanding how into_parts, into_data, from_data work
- Modifying cluster_84-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | insert, plan_account_created, plan_session_opened, plan_session_account_switch, resolve_switch_account (+37) |
| `crates/agenc-ircd-domain/src/command.rs` | into_parts, into_data, from_data |
| `crates/agenc-ircd-domain/src/model.rs` | account_id, next_revision |

## Entry Points

Start here when exploring this area:

- **`into_parts`** (Function) — `crates/agenc-ircd-domain/src/command.rs:226`
- **`into_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:847`
- **`from_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:851`
- **`plan_account_created`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:839`
- **`plan_session_opened`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:854`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_parts` | Function | `crates/agenc-ircd-domain/src/command.rs` | 226 |
| `into_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 847 |
| `from_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 851 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 839 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 854 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 869 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 935 |
| `plan_account_deleted_at_revision` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 988 |
| `plan_account_credential_replaced` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1005 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1137 |
| `account_id` | Function | `crates/agenc-ircd-domain/src/model.rs` | 242 |
| `next_revision` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1347 |
| `insert` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 274 |
| `resolve_switch_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 906 |
| `validate_session_seed` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1182 |
| `validate_account_deletion_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1218 |
| `plan_with_inputs` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1600 |
| `plan_nick` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1670 |
| `reserved_nickname_owner` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1697 |
| `plan_quit` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1706 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Plan_session_opened → At_revision` | cross_community | 4 |
| `Plan_session_account_switch → New` | cross_community | 3 |
| `Plan_session_account_switch → Insert` | intra_community | 3 |
| `Plan_session_opened → Reserved_nickname_owner` | intra_community | 3 |
| `Plan_authorized → Into_data` | cross_community | 3 |
| `Plan_authorized → QueryPlan` | cross_community | 3 |
| `Plan_authorized → From_data` | cross_community | 3 |
| `Plan_with_inputs → Information_kind` | cross_community | 3 |
| `Plan_with_inputs → User_query_kind` | cross_community | 3 |
| `Plan_invite → From_ticks` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 26 calls |
| Cluster_100 | 1 calls |
| Cluster_99 | 1 calls |

## How to Explore

1. `context({name: "into_parts"})` — see callers and callees
2. `query({search_query: "cluster_84"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
