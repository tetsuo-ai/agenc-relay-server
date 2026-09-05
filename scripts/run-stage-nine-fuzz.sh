#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'find "$fuzz_tmp_root" -depth -delete' EXIT
if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    printf '%s\n' 'stage-nine fuzz: cargo-fuzz version mismatch' >&2
    exit 1
fi
for target in wss_upgrade wss_frame; do
    corpus="$fuzz_tmp_root/$target"
    mkdir -p "$corpus"
    cp "$repo_root/test-data/fuzz-corpus/$target/"* "$corpus/"
    (
        cd "$repo_root/fuzz"
        cargo fuzz run --features wss "$target" "$corpus" -- \
            -runs=10000 -seed=20260904 -max_len=18436 -timeout=2 -rss_limit_mb=512
    )
done
printf '%s\n' 'stage-nine WSS fuzz smoke: ok (2 targets, 10000 runs each)'
