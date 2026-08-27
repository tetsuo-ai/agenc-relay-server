---
name: scripts
description: "Skill for the Scripts area of agenc-ircd. 270 symbols across 16 files."
---

# Scripts

270 symbols | 16 files | Cohesion: 86%

## When to Use

- Working with code in `scripts/`
- Understanding how load_toml, vendored_tree_sha256, validate_vendored_patches work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/requirements.py` | task_for, quote, default_binding, task_states, binding_with_current_status (+30) |
| `scripts/check-evidence.py` | required_stage_evidence_ids, load_json, load_toml, validate_catalog, validate_schema (+26) |
| `scripts/generate-stage-one.py` | lower_snake, upper_camel, rust_string, parse_registry, render_registry_round_trip_tests (+23) |
| `scripts/check-workspace.py` | load_toml, vendored_tree_sha256, validate_vendored_patches, validate_toolchain, validate_workspace_manifest (+18) |
| `scripts/check-stage-one.py` | digest, checked_sources, profile_digests, reject_single_byte_changes, parse_registry (+17) |
| `scripts/check-stage-four.py` | load_toml, vendored_tree_sha256, file_sha256, validate_modules, validate_manifests (+14) |
| `scripts/check-coverage.py` | task_states, load_policy, production_source_inventory, validate_source_inventory, validate_policy_data (+13) |
| `scripts/check-source.py` | load_policy, sanitize_rust, blank, line_number, cfg_test_ranges (+12) |
| `scripts/check-stage-three.py` | validate_domain_boundary, extract_post_registration_names, extract_command_match_names, validate_command_coverage, validate_model_test_source (+11) |
| `scripts/run-gate.py` | load_gates, resolve_commands, utc_timestamp, execute, reject_symlink_parents (+10) |

## Entry Points

Start here when exploring this area:

- **`load_toml`** (Function) — `scripts/check-workspace.py:165`
- **`vendored_tree_sha256`** (Function) — `scripts/check-workspace.py:173`
- **`validate_vendored_patches`** (Function) — `scripts/check-workspace.py:197`
- **`validate_toolchain`** (Function) — `scripts/check-workspace.py:225`
- **`validate_workspace_manifest`** (Function) — `scripts/check-workspace.py:252`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `load_toml` | Function | `scripts/check-workspace.py` | 165 |
| `vendored_tree_sha256` | Function | `scripts/check-workspace.py` | 173 |
| `validate_vendored_patches` | Function | `scripts/check-workspace.py` | 197 |
| `validate_toolchain` | Function | `scripts/check-workspace.py` | 225 |
| `validate_workspace_manifest` | Function | `scripts/check-workspace.py` | 252 |
| `validate_dependency_profiles` | Function | `scripts/check-workspace.py` | 289 |
| `dependency_tables` | Function | `scripts/check-workspace.py` | 324 |
| `validate_package_manifests` | Function | `scripts/check-workspace.py` | 343 |
| `validate_direct_dependency_evidence` | Function | `scripts/check-workspace.py` | 398 |
| `cargo_metadata` | Function | `scripts/check-workspace.py` | 425 |
| `packages_from_metadata` | Function | `scripts/check-workspace.py` | 446 |
| `graph_from_packages` | Function | `scripts/check-workspace.py` | 464 |
| `validate_graph` | Function | `scripts/check-workspace.py` | 494 |
| `validate_acyclic` | Function | `scripts/check-workspace.py` | 542 |
| `visit` | Function | `scripts/check-workspace.py` | 547 |
| `validate_release_closure` | Function | `scripts/check-workspace.py` | 562 |
| `validate_lockfile` | Function | `scripts/check-workspace.py` | 584 |
| `validate_dependency_exception` | Function | `scripts/check-workspace.py` | 621 |
| `validate` | Function | `scripts/check-workspace.py` | 655 |
| `expect_rejection` | Function | `scripts/check-workspace.py` | 670 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Self_test → Normative_matches` | cross_community | 7 |
| `Main → Section_number` | cross_community | 7 |
| `Self_test → Section_number` | cross_community | 7 |
| `Self_test → Task_for` | cross_community | 6 |
| `Main → Normative_matches` | cross_community | 6 |
| `Self_test → Normative_matches` | cross_community | 6 |
| `Self_test → Flush` | cross_community | 5 |
| `Self_test → Normalize_text` | cross_community | 5 |
| `Self_test → Sha256_bytes` | cross_community | 5 |
| `Main → Task_for` | intra_community | 5 |

## How to Explore

1. `context({name: "load_toml"})` — see callers and callees
2. `query({search_query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
