---
name: cluster-100
description: "Skill for the Cluster_100 area of agenc-ircd. 8 symbols across 1 files."
---

# Cluster_100

8 symbols | 1 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how parse_reference_vectors_with_limits, parse_manifest_fields, claim_total work
- Modifying cluster_100-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/reference_codec.rs` | parse_reference_vectors_with_limits, parse_manifest_fields, claim_total, manifest_metadata_len, checked_decoded_hex_len (+3) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse_reference_vectors_with_limits` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 271 |
| `parse_manifest_fields` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 327 |
| `claim_total` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 342 |
| `manifest_metadata_len` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 369 |
| `checked_decoded_hex_len` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 393 |
| `validate_manifest_strings` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 400 |
| `is_reference_identifier` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 419 |
| `is_reference_schema` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 434 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |

## How to Explore

1. `context({name: "parse_reference_vectors_with_limits"})` — see callers and callees
2. `query({search_query: "cluster_100"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
