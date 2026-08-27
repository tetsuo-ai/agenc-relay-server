---
name: cluster-5
description: "Skill for the Cluster_5 area of agenc-ircd. 15 symbols across 4 files."
---

# Cluster_5

15 symbols | 4 files | Cohesion: 62%

## When to Use

- Working with code in `crates/`
- Understanding how registration_start, begin_credential_change, into_parts work
- Modifying cluster_5-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/service.rs` | binding, begin_account_creation_with_entropy, begin_authentication_with_entropy, select_authentication_candidate, consume (+6) |
| `crates/agenc-ircd-auth/src/opaque.rs` | registration_start, deserialize_setup |
| `crates/agenc-ircd-auth/src/wire.rs` | into_parts |
| `crates/agenc-ircd-types/src/identifiers.rs` | expose_for_account_service |

## Entry Points

Start here when exploring this area:

- **`registration_start`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:216`
- **`begin_credential_change`** (Function) — `crates/agenc-ircd-auth/src/service.rs:1120`
- **`into_parts`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:96`
- **`expose_for_account_service`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:336`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `registration_start` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 216 |
| `begin_credential_change` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1120 |
| `into_parts` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 96 |
| `expose_for_account_service` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 336 |
| `deserialize_setup` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 363 |
| `binding` | Function | `crates/agenc-ircd-auth/src/service.rs` | 56 |
| `begin_account_creation_with_entropy` | Function | `crates/agenc-ircd-auth/src/service.rs` | 397 |
| `begin_authentication_with_entropy` | Function | `crates/agenc-ircd-auth/src/service.rs` | 762 |
| `select_authentication_candidate` | Function | `crates/agenc-ircd-auth/src/service.rs` | 814 |
| `consume` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1006 |
| `begin_credential_change_with_entropy` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1128 |
| `begin_account_deletion_with_entropy` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1408 |
| `fresh_transaction_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1479 |
| `fresh_opaque_credential_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1483 |
| `duplicate_credential_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1577 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → Validate_match` | cross_community | 5 |
| `Credential_replacement_reuses_identity_and_fences_generation → Validate_match` | cross_community | 4 |
| `Credential_replacement_reuses_identity_and_fences_generation → Expose_for_account_service` | cross_community | 4 |
| `Credential_replacement_reuses_identity_and_fences_generation → Deserialize_setup` | cross_community | 4 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → Fresh_transaction_id` | cross_community | 4 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → AccountDeletionChallenge` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_9 | 6 calls |
| Tests | 4 calls |
| Cluster_2 | 1 calls |
| Cluster_11 | 1 calls |
| Cluster_97 | 1 calls |

## How to Explore

1. `context({name: "registration_start"})` — see callers and callees
2. `query({search_query: "cluster_5"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
