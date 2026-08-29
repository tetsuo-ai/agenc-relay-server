---
name: examples
description: "Skill for the Examples area of agenc-ircd. 33 symbols across 6 files."
---

# Examples

33 symbols | 6 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how native, fill, generate work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | main, qualification_paths, qualify, create_measurement_database, qualification_report (+16) |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill, fill_from, fill_exact, erases_partial_output_when_the_source_fails |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-storage/src/qualification.rs` | native, decode_unsigned |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |

## Entry Points

Start here when exploring this area:

- **`native`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:72`
- **`fill`** (Function) — `crates/agenc-ircd-crypto/src/entropy.rs:15`
- **`generate`** (Function) — `crates/agenc-ircd-crypto/src/signature.rs:206`
- **`decode_unsigned`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:303`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `native` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 72 |
| `fill` | Function | `crates/agenc-ircd-crypto/src/entropy.rs` | 15 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/signature.rs` | 206 |
| `decode_unsigned` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 303 |
| `main` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 29 |
| `qualification_paths` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 34 |
| `qualify` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 45 |
| `create_measurement_database` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 77 |
| `qualification_report` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 103 |
| `initialize_table` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 133 |
| `qualification_corpus` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 376 |
| `encode_raw_log` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 388 |
| `create_private_file` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 408 |
| `write_private_file` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 417 |
| `create` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 428 |
| `measure_growth` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 86 |
| `prepare_case` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 151 |
| `run_case` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 169 |
| `insert_value` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 216 |
| `delete_value` | Function | `crates/agenc-ircd-storage/examples/storage-qualification.rs` | 237 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Generate → Fill_from` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 8 calls |
| Cluster_172 | 1 calls |

## How to Explore

1. `context({name: "native"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
