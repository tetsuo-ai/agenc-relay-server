#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-ircd-runtime --test stage_six_soak --locked
echo "stage-six deterministic CI soak: ok"
