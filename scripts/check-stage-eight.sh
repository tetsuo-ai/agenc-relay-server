#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 scripts/run-gate.py stage-eight-implementation
echo "stage-eight implementation checks: ok; exact-SHA closure is recorded separately"
