#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'rm -rf "$fuzz_tmp_root"' EXIT

if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    echo "stage-four fuzz: cargo-fuzz version mismatch" >&2
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
        -seed=20260827 \
        -max_len=4726 \
        -timeout=2 \
        -rss_limit_mb=512
    )
}

run_target account_service_envelope account-service-envelope
run_target crypto_wrappers crypto-wrappers

echo "stage-four fuzz smoke: ok (2 targets, 10000 runs each)"
