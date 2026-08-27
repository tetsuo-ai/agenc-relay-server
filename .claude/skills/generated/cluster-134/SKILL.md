---
name: cluster-134
description: "Skill for the Cluster_134 area of agenc-ircd. 15 symbols across 1 files."
---

# Cluster_134

15 symbols | 1 files | Cohesion: 88%

## When to Use

- Working with code in `crates/`
- Understanding how is_allowed_for, validate work
- Modifying cluster_134-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/model.rs` | is_allowed_for, validate, content_policy_is_valid, pending_removals_are_valid, identities_and_limits_are_valid (+10) |

## Entry Points

Start here when exploring this area:

- **`is_allowed_for`** (Function) — `crates/agenc-ircd-domain/src/model.rs:302`
- **`validate`** (Function) — `crates/agenc-ircd-domain/src/model.rs:980`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `is_allowed_for` | Function | `crates/agenc-ircd-domain/src/model.rs` | 302 |
| `validate` | Function | `crates/agenc-ircd-domain/src/model.rs` | 980 |
| `content_policy_is_valid` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1002 |
| `pending_removals_are_valid` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1014 |
| `identities_and_limits_are_valid` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1022 |
| `registered_owner_is_preserved` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1032 |
| `membership_roles_are_current` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1037 |
| `validate_sessions` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1252 |
| `validate_session` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1265 |
| `validate_session_account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1290 |
| `validate_channels` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1308 |
| `validate_channel_memberships` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1325 |
| `validate_accounts` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1353 |
| `validate_account_deletion_challenges` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1387 |
| `validate_network_invite_count` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1415 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 1 calls |

## How to Explore

1. `context({name: "is_allowed_for"})` — see callers and callees
2. `query({search_query: "cluster_134"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
