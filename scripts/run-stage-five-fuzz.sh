#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'rm -rf "$fuzz_tmp_root"' EXIT

if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    echo "stage-five fuzz: cargo-fuzz version mismatch" >&2
    exit 1
fi

run_target() {
    local target="$1"
    local corpus="$fuzz_tmp_root/$target"
    mkdir -p "$corpus"
    (
        cd "$repo_root/fuzz"
        cargo fuzz run "$target" "$corpus" -- \
            -runs=10000 \
            -seed=20260827 \
            -max_len=1048576 \
            -timeout=2 \
            -rss_limit_mb=1024
    )
}

run_target storage_codecs
run_target backup_stream

echo "stage-five fuzz smoke: ok (2 targets, 10000 runs each)"
