#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-relay-testkit --test federation_model --locked
echo "stage-seven bounded federation model: ok (exhaustive to the recorded depth)"
