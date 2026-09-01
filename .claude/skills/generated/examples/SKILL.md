---
name: examples
description: "Skill for the Examples area of agenc-ircd. 73 symbols across 12 files."
---

# Examples

73 symbols | 12 files | Cohesion: 71%

## When to Use

- Working with code in `crates/`
- Understanding how fill, generate, validate_migration_profile work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/platform.rs` | new, create, publish, open, open_with_faults (+17) |
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | measure_growth, prepare_case, run_case, insert_value, delete_value (+16) |
| `crates/agenc-ircd-storage/src/engine.rs` | install_scanned_checkpoint, commit_prepared_checkpoint, commit_inner, validate_batch_head, reserve_nonce_block (+5) |
| `crates/agenc-ircd-storage/src/qualification.rs` | measure_file, measure_required_corpus, measure_required_file_set, finish, decode_unsigned (+1) |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill, fill_from, erases_partial_output_when_the_source_fails |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | signed_growth_report_is_exact_tuple_authority, qualification_required_file_set_measures_every_named_durable_case |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |
| `crates/agenc-ircd-storage/src/construction.rs` | validate_migration_profile |

## Entry Points

Start here when exploring this area:

- **`fill`** (Function) — `crates/agenc-ircd-crypto/src/entropy.rs:15`
- **`generate`** (Function) — `crates/agenc-ircd-crypto/src/signature.rs:206`
- **`validate_migration_profile`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:494`
- **`draw_nonces_with_faults`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:3059`
- **`check`** (Function) — `crates/agenc-ircd-storage/src/fault.rs:182`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `fill` | Function | `crates/agenc-ircd-crypto/src/entropy.rs` | 15 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/signature.rs` | 206 |
| `validate_migration_profile` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 494 |
| `draw_nonces_with_faults` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3059 |
| `check` | Function | `crates/agenc-ircd-storage/src/fault.rs` | 182 |
| `new` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 121 |
| `publish` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 209 |
| `open` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 283 |
| `open_with_faults` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 291 |
| `open_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 406 |
| `create_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 420 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 434 |
| `replace_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 470 |
| `create_recovery_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 529 |
| `admit_backup_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 665 |
| `measure_file` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 416 |
| `measure_required_corpus` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 481 |
| `measure_required_file_set` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 497 |
| `finish` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 509 |
| `decode_unsigned` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 303 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Init → Fill_from` | cross_community | 6 |
| `Clean_init_reopens_for_onboarding_and_repeated_init_is_refused → Fill_from` | cross_community | 5 |
| `Construction_scan → Validate_file` | cross_community | 4 |
| `Construction_scan → Require_same_filesystem` | cross_community | 4 |
| `Start_backup → Validate_file` | cross_community | 4 |
| `Start_backup → Require_same_filesystem` | cross_community | 4 |
| `Startup_scan → Validate_file` | cross_community | 4 |
| `Startup_scan → Require_same_filesystem` | cross_community | 4 |
| `Commit_inner → Tbs` | intra_community | 3 |
| `Commit_inner → Expected_storage_commit_sequence` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 33 calls |
| Cluster_185 | 3 calls |
| Cluster_471 | 2 calls |
| Cluster_178 | 1 calls |
| Cluster_443 | 1 calls |
| State_core | 1 calls |
| Cluster_460 | 1 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "fill"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
