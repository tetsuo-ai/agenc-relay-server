---
name: cluster-85
description: "Skill for the Cluster_85 area of agenc-ircd. 11 symbols across 1 files."
---

# Cluster_85

11 symbols | 1 files | Cohesion: 91%

## When to Use

- Working with code in `crates/`
- Understanding how is_allowed_for, validate work
- Modifying cluster_85-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/model.rs` | is_allowed_for, validate, identities_and_limits_are_valid, registered_owner_is_preserved, membership_roles_are_current (+6) |

## Entry Points

Start here when exploring this area:

- **`is_allowed_for`** (Function) — `crates/agenc-ircd-domain/src/model.rs:302`
- **`validate`** (Function) — `crates/agenc-ircd-domain/src/model.rs:968`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `is_allowed_for` | Function | `crates/agenc-ircd-domain/src/model.rs` | 302 |
| `validate` | Function | `crates/agenc-ircd-domain/src/model.rs` | 968 |
| `identities_and_limits_are_valid` | Function | `crates/agenc-ircd-domain/src/model.rs` | 987 |
| `registered_owner_is_preserved` | Function | `crates/agenc-ircd-domain/src/model.rs` | 997 |
| `membership_roles_are_current` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1002 |
| `validate_sessions` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1210 |
| `validate_session` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1222 |
| `validate_session_account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1246 |
| `validate_channels` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1262 |
| `validate_channel_memberships` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1284 |
| `validate_accounts` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1312 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 1 calls |

## How to Explore

1. `context({name: "is_allowed_for"})` — see callers and callees
2. `query({search_query: "cluster_85"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
