#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-relay-runtime --release --test e2ee_load --locked -- --nocapture
echo "stage-eight bounded load harness: ok (report under target/stage-eight-load.json)"
