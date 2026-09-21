#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-relay-testkit --test e2ee_model --locked
echo "stage-eight bounded encrypted model: ok (exhaustive to the recorded depth)"
