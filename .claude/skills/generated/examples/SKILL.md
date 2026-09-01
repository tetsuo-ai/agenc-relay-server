---
name: examples
description: "Skill for the Examples area of agenc-ircd. 43 symbols across 10 files."
---

# Examples

43 symbols | 10 files | Cohesion: 70%

## When to Use

- Working with code in `crates/`
- Understanding how measure_file, measure_required_corpus, measure_required_file_set work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | measure_growth, prepare_case, run_case, insert_value, delete_value (+16) |
| `crates/agenc-ircd-storage/src/qualification.rs` | measure_file, measure_required_corpus, measure_required_file_set, finish, decode_unsigned (+1) |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill, fill_from, fill_exact, erases_partial_output_when_the_source_fails |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | signed_growth_report_is_exact_tuple_authority, qualification_required_file_set_measures_every_named_durable_case |
| `crates/agenc-ircd-storage/src/construction_directory.rs` | anonymous_plan_file, random_scratch_name |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-runtime/src/daemon.rs` | registered_commands |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | storage_qualification_component_hash |

## Entry Points

Start here when exploring this area:

- **`measure_file`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:416`
- **`measure_required_corpus`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:481`
- **`measure_required_file_set`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:497`
- **`finish`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:509`
- **`fill`** (Function) — `crates/agenc-ircd-crypto/src/entropy.rs:15`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `measure_file` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 416 |
| `measure_required_corpus` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 481 |
| `measure_required_file_set` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 497 |
| `finish` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 509 |
| `fill` | Function | `crates/agenc-ircd-crypto/src/entropy.rs` | 15 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/signature.rs` | 206 |
| `anonymous_plan_file` | Function | `crates/agenc-ircd-storage/src/construction_directory.rs` | 206 |
| `decode_unsigned` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 303 |
| `storage_qualification_component_hash` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 399 |
| `native` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 72 |
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

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Clean_init_reopens_for_onboarding_and_repeated_init_is_refused → Fill_from` | cross_community | 5 |
| `Edge_init_imports_public_pins_without_creating_coordinator_secrets → Fill_from` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 12 calls |
| Cluster_178 | 1 calls |
| Cluster_189 | 1 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "measure_file"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
