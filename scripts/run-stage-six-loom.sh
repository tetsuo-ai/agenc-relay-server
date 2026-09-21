#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-relay-runtime --test loom_models --locked
echo "stage-six Loom schedules: ok (6 bounded models)"
