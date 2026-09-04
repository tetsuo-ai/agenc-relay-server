#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'find "$fuzz_tmp_root" -depth -delete' EXIT

if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    echo "stage-eight fuzz: cargo-fuzz version mismatch" >&2
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
            -seed=20260904 \
            -max_len=65536 \
            -timeout=2 \
            -rss_limit_mb=512
    )
}

run_target e2ee_object e2ee-object
run_target e2ee_mls_outer e2ee-mls-outer
run_target e2ee_fragment e2ee-fragment
run_target e2ee_identity_chain e2ee-identity-chain
run_target e2ee_tags e2ee-tags

echo "stage-eight fuzz smoke: ok (5 targets, 10000 runs each)"
