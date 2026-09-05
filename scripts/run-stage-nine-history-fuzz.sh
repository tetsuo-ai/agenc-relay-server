#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'find "$fuzz_tmp_root" -depth -delete' EXIT
if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    printf '%s\n' 'stage-nine history fuzz: cargo-fuzz version mismatch' >&2
    exit 1
fi
cp "$repo_root/test-data/fuzz-corpus/history_records/"* "$fuzz_tmp_root/"
cd "$repo_root/fuzz"
cargo fuzz run history_records "$fuzz_tmp_root" -- \
    -runs=10000 -seed=20260904 -max_len=65536 -timeout=2 -rss_limit_mb=512
printf '%s\n' 'stage-nine history record fuzz smoke: ok (10000 runs)'
