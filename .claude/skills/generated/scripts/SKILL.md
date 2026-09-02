---
name: scripts
description: "Skill for the Scripts area of agenc-ircd. 340 symbols across 20 files."
---

# Scripts

340 symbols | 20 files | Cohesion: 87%

## When to Use

- Working with code in `scripts/`
- Understanding how load_json, load_toml, validate_catalog work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/check-evidence.py` | load_json, load_toml, validate_catalog, validate_schema, git_environment (+36) |
| `scripts/requirements.py` | task_for, quote, default_binding, task_states, binding_with_current_status (+30) |
| `scripts/generate-stage-one.py` | lower_snake, upper_camel, rust_string, parse_registry, render_registry_round_trip_tests (+23) |
| `scripts/check-workspace.py` | load_toml, vendored_tree_sha256, validate_vendored_patches, validate_toolchain_policy, validate_toolchain (+20) |
| `scripts/check-stage-one.py` | digest, checked_sources, profile_digests, reject_single_byte_changes, parse_registry (+17) |
| `scripts/run-gate.py` | load_gates, resolve_commands, utc_timestamp, execute, reject_symlink_parents (+14) |
| `scripts/check-stage-four.py` | load_toml, vendored_tree_sha256, file_sha256, validate_modules, validate_manifests (+14) |
| `scripts/check-coverage.py` | task_states, load_policy, production_source_inventory, validate_source_inventory, validate_policy_data (+13) |
| `scripts/check-source.py` | load_policy, sanitize_rust, blank, line_number, cfg_test_ranges (+12) |
| `scripts/check-rust-components.py` | terminate_process_group, run_bounded, checked_stdout, single_output_line, parse_sysroot (+11) |

## Entry Points

Start here when exploring this area:

- **`load_json`** (Function) — `scripts/check-evidence.py:369`
- **`load_toml`** (Function) — `scripts/check-evidence.py:388`
- **`validate_catalog`** (Function) — `scripts/check-evidence.py:396`
- **`validate_schema`** (Function) — `scripts/check-evidence.py:505`
- **`git_environment`** (Function) — `scripts/check-evidence.py:557`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `load_json` | Function | `scripts/check-evidence.py` | 369 |
| `load_toml` | Function | `scripts/check-evidence.py` | 388 |
| `validate_catalog` | Function | `scripts/check-evidence.py` | 396 |
| `validate_schema` | Function | `scripts/check-evidence.py` | 505 |
| `git_environment` | Function | `scripts/check-evidence.py` | 557 |
| `git_bytes` | Function | `scripts/check-evidence.py` | 573 |
| `require_complete_history` | Function | `scripts/check-evidence.py` | 591 |
| `validate_index_bytes` | Function | `scripts/check-evidence.py` | 604 |
| `commit_blob` | Function | `scripts/check-evidence.py` | 646 |
| `commit_blob_sha256` | Function | `scripts/check-evidence.py` | 651 |
| `canonical_source_sha256` | Function | `scripts/check-evidence.py` | 656 |
| `load_toolchain_policy` | Function | `scripts/check-evidence.py` | 910 |
| `source_toolchain_policy` | Function | `scripts/check-evidence.py` | 934 |
| `validate` | Function | `scripts/check-evidence.py` | 1154 |
| `source_gate_policy` | Function | `scripts/check-evidence.py` | 1295 |
| `resolve` | Function | `scripts/check-evidence.py` | 1329 |
| `validate_closure_entries` | Function | `scripts/check-evidence.py` | 1580 |
| `validate_closure` | Function | `scripts/check-evidence.py` | 1667 |
| `expect_rejection` | Function | `scripts/check-evidence.py` | 1718 |
| `self_test` | Function | `scripts/check-evidence.py` | 1734 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Self_test → Normative_matches` | cross_community | 7 |
| `Main → Section_number` | cross_community | 7 |
| `Self_test → Task_for` | cross_community | 6 |
| `Main → Normative_matches` | cross_community | 6 |
| `Self_test → Flush` | cross_community | 5 |
| `Self_test → Normalize_text` | cross_community | 5 |
| `Self_test → Sha256_bytes` | cross_community | 5 |
| `Main → Task_for` | intra_community | 5 |
| `Self_test → Split_sentences` | cross_community | 4 |
| `Main → Flush` | cross_community | 4 |

## How to Explore

1. `context({name: "load_json"})` — see callers and callees
2. `query({search_query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
