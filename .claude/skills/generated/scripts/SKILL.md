---
name: scripts
description: "Skill for the Scripts area of agenc-ircd. 181 symbols across 12 files."
---

# Scripts

181 symbols | 12 files | Cohesion: 90%

## When to Use

- Working with code in `scripts/`
- Understanding how load_toml, validate_toolchain, validate_workspace_manifest work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/requirements.py` | quote, render_bindings, load_bindings, validate_bindings, merge_bindings (+26) |
| `scripts/generate-stage-one.py` | lower_snake, upper_camel, rust_string, parse_registry, render_registry_round_trip_tests (+23) |
| `scripts/check-stage-one.py` | digest, checked_sources, profile_digests, reject_single_byte_changes, parse_registry (+17) |
| `scripts/check-workspace.py` | load_toml, validate_toolchain, validate_workspace_manifest, validate_dependency_profiles, dependency_tables (+16) |
| `scripts/check-evidence.py` | load_json, load_toml, validate_catalog, validate_schema, git_bytes (+13) |
| `scripts/check-source.py` | load_policy, sanitize_rust, blank, line_number, cfg_test_ranges (+12) |
| `scripts/check-stage-two.py` | validate_capabilities, validate_modules, check_generator, validate, fail (+9) |
| `scripts/check-baseline.py` | sha256_file, git_bytes, validate_frozen_commit, frozen_blob, frozen_mode (+4) |
| `scripts/check-ci.py` | live_workflow_text, validate_workflow, validate_manifest, load_manifest_text, validate (+4) |
| `scripts/run-gate.py` | load_gates, resolve_commands, command_environment, execute, fail (+1) |

## Entry Points

Start here when exploring this area:

- **`load_toml`** (Function) — `scripts/check-workspace.py:137`
- **`validate_toolchain`** (Function) — `scripts/check-workspace.py:145`
- **`validate_workspace_manifest`** (Function) — `scripts/check-workspace.py:172`
- **`validate_dependency_profiles`** (Function) — `scripts/check-workspace.py:206`
- **`dependency_tables`** (Function) — `scripts/check-workspace.py:237`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `load_toml` | Function | `scripts/check-workspace.py` | 137 |
| `validate_toolchain` | Function | `scripts/check-workspace.py` | 145 |
| `validate_workspace_manifest` | Function | `scripts/check-workspace.py` | 172 |
| `validate_dependency_profiles` | Function | `scripts/check-workspace.py` | 206 |
| `dependency_tables` | Function | `scripts/check-workspace.py` | 237 |
| `validate_package_manifests` | Function | `scripts/check-workspace.py` | 256 |
| `validate_direct_dependency_evidence` | Function | `scripts/check-workspace.py` | 311 |
| `cargo_metadata` | Function | `scripts/check-workspace.py` | 338 |
| `packages_from_metadata` | Function | `scripts/check-workspace.py` | 359 |
| `graph_from_packages` | Function | `scripts/check-workspace.py` | 377 |
| `validate_graph` | Function | `scripts/check-workspace.py` | 407 |
| `validate_acyclic` | Function | `scripts/check-workspace.py` | 455 |
| `visit` | Function | `scripts/check-workspace.py` | 460 |
| `validate_release_closure` | Function | `scripts/check-workspace.py` | 475 |
| `validate_lockfile` | Function | `scripts/check-workspace.py` | 497 |
| `validate_dependency_exception` | Function | `scripts/check-workspace.py` | 530 |
| `validate` | Function | `scripts/check-workspace.py` | 564 |
| `expect_rejection` | Function | `scripts/check-workspace.py` | 578 |
| `self_test` | Function | `scripts/check-workspace.py` | 591 |
| `fail` | Function | `scripts/check-workspace.py` | 663 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Main → Normative_matches` | cross_community | 6 |
| `Self_test → Normative_matches` | cross_community | 6 |
| `Main → Semantic_opaque` | cross_community | 6 |
| `Main → Length_prefix` | cross_community | 6 |
| `Main → Semantic_enum` | cross_community | 6 |
| `Main → Require_string` | cross_community | 5 |
| `Main → Blank` | intra_community | 5 |
| `Main → Cfg_test_ranges` | intra_community | 5 |
| `Self_test → Blank` | intra_community | 5 |
| `Main → Length_width` | cross_community | 5 |

## How to Explore

1. `context({name: "load_toml"})` — see callers and callees
2. `query({search_query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
