#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 scripts/run-gate.py stage-six-implementation
echo "stage-six implementation checks: ok; exact-SHA closure is recorded separately"
