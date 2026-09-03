#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'find "$fuzz_tmp_root" -depth -delete' EXIT

if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    echo "stage-seven fuzz: cargo-fuzz version mismatch" >&2
    exit 1
fi

run_target() {
    local target="$1"
    local corpus_name="$2"
    local corpus="$fuzz_tmp_root/$corpus_name"
    mkdir -p "$corpus"
    cp "$repo_root/test-data/fuzz-corpus/$corpus_name/"* "$corpus/"
    (
        cd "$repo_root/fuzz"
        cargo fuzz run "$target" "$corpus" -- \
            -runs=10000 \
            -seed=20260903 \
            -max_len=65536 \
            -timeout=2 \
            -rss_limit_mb=512
    )
}

run_target federation_object federation-object
run_target federation_fragment federation-fragment

echo "stage-seven fuzz smoke: ok (2 targets, 10000 runs each)"
