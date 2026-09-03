---
name: examples
description: "Skill for the Examples area of agenc-ircd. 47 symbols across 8 files."
---

# Examples

47 symbols | 8 files | Cohesion: 74%

## When to Use

- Working with code in `crates/`
- Understanding how measure_file, measure_required_corpus, measure_required_file_set work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | measure_growth, prepare_case, run_case, insert_value, delete_value (+16) |
| `crates/agenc-ircd-crypto/src/tls_ticket.rs` | generate, key_id, seal, generate_with, seal_with (+6) |
| `crates/agenc-ircd-storage/src/qualification.rs` | measure_file, measure_required_corpus, measure_required_file_set, finish, native (+1) |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | signed_growth_report_is_exact_tuple_authority, qualification_required_file_set_measures_every_named_durable_case |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |

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
| `generate` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 48 |
| `key_id` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 54 |
| `seal` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 59 |
| `native` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 72 |
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

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 13 calls |
| Cluster_198 | 2 calls |
| Cluster_201 | 1 calls |
| Cluster_197 | 1 calls |
| State_core | 1 calls |

## How to Explore

1. `context({name: "measure_file"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
