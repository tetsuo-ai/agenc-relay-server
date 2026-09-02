---
name: examples
description: "Skill for the Examples area of agenc-ircd. 35 symbols across 8 files."
---

# Examples

35 symbols | 8 files | Cohesion: 69%

## When to Use

- Working with code in `crates/`
- Understanding how fill, generate, decode_unsigned work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | measure_growth, prepare_case, run_case, insert_value, delete_value (+16) |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill, fill_from, erases_partial_output_when_the_source_fails |
| `crates/agenc-ircd-runtime/src/offline.rs` | random_32, unique_suffix |
| `crates/agenc-ircd-storage/src/qualification.rs` | decode_unsigned, native |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | storage_qualification_component_hash |

## Entry Points

Start here when exploring this area:

- **`fill`** (Function) — `crates/agenc-ircd-crypto/src/entropy.rs:15`
- **`generate`** (Function) — `crates/agenc-ircd-crypto/src/signature.rs:206`
- **`decode_unsigned`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:303`
- **`storage_qualification_component_hash`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:399`
- **`native`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:72`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `fill` | Function | `crates/agenc-ircd-crypto/src/entropy.rs` | 15 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/signature.rs` | 206 |
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
| `main` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 29 |
| `qualification_paths` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 34 |
| `qualify` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 45 |
| `create_measurement_database` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 77 |
| `initialize_table` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 133 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Cluster_544 | 1 calls |
| Cluster_211 | 1 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "fill"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
