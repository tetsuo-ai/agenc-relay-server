---
name: admission
description: "Skill for the Admission area of agenc-ircd. 58 symbols across 3 files."
---

# Admission

58 symbols | 3 files | Cohesion: 86%

## When to Use

- Working with code in `crates/`
- Understanding how default_rate, hard_rate, new work
- Modifying admission-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admission/buckets.rs` | default_rate, hard_rate, new, fixed, within (+31) |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | new, with_ceiling, connection_opened, connection_closed, erase_idle (+6) |
| `crates/agenc-ircd-runtime/src/admission/overload.rs` | new, classify, default, usage_reaches, select_evictions (+6) |

## Entry Points

Start here when exploring this area:

- **`default_rate`** (Function) — `crates/agenc-ircd-runtime/src/admission/buckets.rs:112`
- **`hard_rate`** (Function) — `crates/agenc-ircd-runtime/src/admission/buckets.rs:134`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/admission/buckets.rs:165`
- **`within`** (Function) — `crates/agenc-ircd-runtime/src/admission/buckets.rs:218`
- **`defaults`** (Function) — `crates/agenc-ircd-runtime/src/admission/buckets.rs:233`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `default_rate` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 112 |
| `hard_rate` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 134 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 165 |
| `within` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 218 |
| `defaults` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 233 |
| `set` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 264 |
| `from_digest_bytes` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 284 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 443 |
| `len` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 459 |
| `domain_snapshot` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 504 |
| `apply_domain_charges` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 519 |
| `erase_key` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 536 |
| `domain_bucket` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 607 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 37 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 43 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 54 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 77 |
| `erase_idle` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 95 |
| `rate` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 255 |
| `full` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 323 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Apply_domain_charges → Fixed` | cross_community | 7 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Fixed` | cross_community | 5 |
| `Apply_domain_charges → New` | cross_community | 5 |
| `Apply_domain_charges → Full` | cross_community | 4 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Within` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Cluster_191 | 3 calls |
| Listener | 3 calls |

## How to Explore

1. `context({name: "default_rate"})` — see callers and callees
2. `query({search_query: "admission"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
