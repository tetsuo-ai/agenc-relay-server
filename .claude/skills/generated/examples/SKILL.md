---
name: examples
description: "Skill for the Examples area of agenc-ircd. 38 symbols across 7 files."
---

# Examples

38 symbols | 7 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how measure_required_corpus, measure_required_file_set, finish work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | measure_growth, prepare_case, run_case, insert_value, delete_value (+16) |
| `crates/agenc-ircd-storage/src/qualification.rs` | measure_required_corpus, measure_required_file_set, finish, native, decode_unsigned |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill, fill_from, fill_exact, erases_partial_output_when_the_source_fails |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | signed_growth_report_is_exact_tuple_authority, qualification_required_file_set_measures_every_named_durable_case |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |

## Entry Points

Start here when exploring this area:

- **`measure_required_corpus`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:481`
- **`measure_required_file_set`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:497`
- **`finish`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:509`
- **`native`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:72`
- **`fill`** (Function) — `crates/agenc-ircd-crypto/src/entropy.rs:15`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `measure_required_corpus` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 481 |
| `measure_required_file_set` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 497 |
| `finish` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 509 |
| `native` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 72 |
| `fill` | Function | `crates/agenc-ircd-crypto/src/entropy.rs` | 15 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/signature.rs` | 202 |
| `decode_unsigned` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 303 |
| `measure_growth` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 86 |
| `prepare_case` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 151 |
| `run_case` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 169 |
| `insert_value` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 216 |
| `delete_value` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 237 |
| `insert_range` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 258 |
| `delete_range` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 287 |
| `mixed_max_records` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 310 |
| `fragment_tree` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 340 |
| `record_key` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 370 |
| `signed_growth_report_is_exact_tuple_authority` | Function | `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | 555 |
| `qualification_required_file_set_measures_every_named_durable_case` | Function | `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | 1197 |
| `main` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 29 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Generate → Fill_from` | cross_community | 6 |
| `Startup_scan → Fill_from` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Cluster_242 | 3 calls |
| Cluster_110 | 1 calls |
| Cluster_282 | 1 calls |

## How to Explore

1. `context({name: "measure_required_corpus"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
