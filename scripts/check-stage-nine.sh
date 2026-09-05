#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python3 scripts/run-gate.py stage-nine-implementation
printf '%s\n' 'stage-nine implementation checks: ok; exact-SHA closure is recorded separately'
