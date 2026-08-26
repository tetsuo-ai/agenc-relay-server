#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_tmp_root="$(mktemp -d)"
trap 'rm -rf "$fuzz_tmp_root"' EXIT

if [[ "$(cargo fuzz --version)" != "cargo-fuzz 0.13.2" ]]; then
    echo "stage-two fuzz: cargo-fuzz version mismatch" >&2
    exit 1
fi

targets=(tcp_framing websocket parse_render client_state)
for target in "${targets[@]}"; do
    corpus="$fuzz_tmp_root/$target"
    mkdir -p "$corpus"
    cp "$repo_root/test-data/fuzz-corpus/client-wire/$target/"* "$corpus/"
    (
        cd "$repo_root/fuzz"
        cargo fuzz run "$target" "$corpus" -- \
            -runs=10000 \
            -seed=20260824 \
            -max_len=32768 \
            -timeout=2 \
            -rss_limit_mb=512
    )
done

echo "stage-two fuzz smoke: ok (4 targets, 10000 runs each)"
