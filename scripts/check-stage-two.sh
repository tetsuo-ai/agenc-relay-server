#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

require_exact_version() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    if [[ "$actual" != "$expected" ]]; then
        echo "stage-two implementation checks: $label version mismatch: $actual != $expected" >&2
        exit 1
    fi
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "stage-two implementation checks: required command is missing: $command_name" >&2
        exit 1
    fi
}

require_command cargo-deny
require_command cargo-audit
require_command cargo-fuzz
require_exact_version "rustc" "$(rustc --version | awk '{print $1 " " $2}')" "rustc 1.98.0"
require_exact_version "fuzz rustc" "$(rustup run nightly-2026-08-24 rustc --version)" "rustc 1.100.0-nightly (fb6531d55 2026-08-23)"
require_exact_version "cargo-deny" "$(cargo deny --version)" "cargo-deny 0.20.2"
require_exact_version "cargo-audit" "$(cargo audit --version)" "cargo-audit-audit 0.22.2"
require_exact_version "cargo-llvm-cov" "$(cargo llvm-cov --version)" "cargo-llvm-cov 0.9.0"
require_exact_version "cargo-fuzz" "$(cargo fuzz --version)" "cargo-fuzz 0.13.2"

python3 scripts/run-gate.py stage-two-implementation
echo "stage-two implementation checks: ok; stage closure is validated separately"
