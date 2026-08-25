#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

require_exact_version() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    if [[ "$actual" != "$expected" ]]; then
        echo "stage-zero gate: $label version mismatch: $actual != $expected" >&2
        exit 1
    fi
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "stage-zero gate: required command is missing: $command_name" >&2
        exit 1
    fi
}

run() {
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
    "$@"
}

require_command cargo-deny
require_command cargo-audit
require_exact_version "rustc" "$(rustc --version | awk '{print $1 " " $2}')" "rustc 1.98.0"
require_exact_version "cargo-deny" "$(cargo deny --version)" "cargo-deny 0.20.2"
require_exact_version "cargo-audit" "$(cargo audit --version)" "cargo-audit-audit 0.22.2"
require_exact_version "cargo-llvm-cov" "$(cargo llvm-cov --version)" "cargo-llvm-cov 0.9.0"

run bash scripts/check-spec.sh
run python3 scripts/check-baseline.py
run python3 scripts/requirements.py check
run python3 scripts/requirements.py self-test
run python3 scripts/check-workspace.py check
run python3 scripts/check-workspace.py self-test
run python3 scripts/check-source.py check
run python3 scripts/check-source.py self-test
run python3 scripts/check-evidence.py check
run python3 scripts/check-evidence.py self-test
run python3 scripts/check-ci.py check
run python3 scripts/check-ci.py self-test

run cargo fmt --all --check
run cargo check --workspace --all-targets --all-features --locked
run cargo check --workspace --all-targets --all-features --locked --target x86_64-unknown-linux-gnu
run cargo check --workspace --all-targets --all-features --locked --target aarch64-unknown-linux-gnu
run cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run cargo test --workspace --all-features --locked
run cargo test --workspace --doc --all-features --locked
run cargo tree --workspace --all-features --locked
run cargo deny check
run cargo audit --deny warnings
run env RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --all-features --branch \
    --json --summary-only --output-path target/stage-zero-coverage.json
run python3 scripts/check-coverage.py target/stage-zero-coverage.json

echo "stage-zero gate: ok"
