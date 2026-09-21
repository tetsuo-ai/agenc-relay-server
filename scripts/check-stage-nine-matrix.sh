#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export CARGO_INCREMENTAL=0
# Preserve each binary while other validation uses the ordinary target directory.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}/stage-nine-matrix"
matrix_binaries="$(mktemp -d)"
trap 'find "$matrix_binaries" -depth -delete' EXIT
target_directory="$(cargo metadata --no-deps --format-version 1 --locked | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
for profile in none wss history wss,history; do
    feature_args=(--no-default-features)
    if [[ "$profile" != none ]]; then
        feature_args+=(--features "$profile")
    fi
    cargo check --workspace --all-targets --locked "${feature_args[@]}"
    cargo test -p agenc-relay-server --test stage_six_daemon --locked "${feature_args[@]}" \
        profile_matrix::optional_profile_configuration_matrix_resolves_before_storage_writes
    if [[ "$profile" == none || "$profile" == wss ]]; then
        cp "$target_directory/debug/arcd" "$matrix_binaries/$profile"
    fi
done
AGENC_STAGE09_DISABLED_BINARIES="$matrix_binaries/none:$matrix_binaries/wss" \
    cargo test -p agenc-relay-server --test stage_six_daemon --locked --no-default-features \
        --features wss,history history::disabled::disabled_history_startup_preserves_original_rows
printf '%s\n' 'stage-nine profile matrix: ok (4 builds, 9 admitted configurations, 7 refusals before storage writes)'
