---
name: cluster-6
description: "Skill for the Cluster_6 area of agenc-ircd. 14 symbols across 1 files."
---

# Cluster_6

14 symbols | 1 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how new, begin_account_creation, begin_credential_change work
- Modifying cluster_6-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/service.rs` | new, binding, begin_account_creation, consume, begin_credential_change (+9) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-auth/src/service.rs:37`
- **`begin_account_creation`** (Function) — `crates/agenc-ircd-auth/src/service.rs:145`
- **`begin_credential_change`** (Function) — `crates/agenc-ircd-auth/src/service.rs:567`
- **`begin_account_deletion`** (Function) — `crates/agenc-ircd-auth/src/service.rs:724`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-auth/src/service.rs` | 37 |
| `begin_account_creation` | Function | `crates/agenc-ircd-auth/src/service.rs` | 145 |
| `begin_credential_change` | Function | `crates/agenc-ircd-auth/src/service.rs` | 567 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-auth/src/service.rs` | 724 |
| `binding` | Function | `crates/agenc-ircd-auth/src/service.rs` | 51 |
| `consume` | Function | `crates/agenc-ircd-auth/src/service.rs` | 450 |
| `duplicate_credential_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 799 |
| `context` | Function | `crates/agenc-ircd-auth/src/service.rs` | 813 |
| `account` | Function | `crates/agenc-ircd-auth/src/service.rs` | 822 |
| `fresh_proof` | Function | `crates/agenc-ircd-auth/src/service.rs` | 830 |
| `deletion_confirmation_is_revision_bound_and_consumed_on_failure` | Function | `crates/agenc-ircd-auth/src/service.rs` | 843 |
| `deletion_confirmation_accepts_the_unchanged_snapshot` | Function | `crates/agenc-ircd-auth/src/service.rs` | 867 |
| `fresh_authentication_has_an_inclusive_five_minute_boundary` | Function | `crates/agenc-ircd-auth/src/service.rs` | 884 |
| `destructive_proofs_and_deletion_confirmations_reject_every_substitution` | Function | `crates/agenc-ircd-auth/src/service.rs` | 908 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → AccountSnapshot` | intra_community | 5 |
| `Destructive_proofs_and_deletion_confirmations_reject_every_substitution → AccountSnapshot` | intra_community | 4 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → Fill_from` | cross_community | 4 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → From_ticks` | cross_community | 4 |
| `Destructive_proofs_and_deletion_confirmations_reject_every_substitution → From_ticks` | cross_community | 3 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → Consume` | intra_community | 3 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → AccountDeletionChallenge` | intra_community | 3 |
| `Deletion_confirmation_is_revision_bound_and_consumed_on_failure → FreshAuthenticationProof` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Cluster_3 | 3 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_6"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
