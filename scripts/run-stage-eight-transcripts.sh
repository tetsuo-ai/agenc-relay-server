#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo nextest run -p agenc-relay-e2ee --all-features --locked
cargo nextest run -p agenc-relay-domain --lib e2ee:: --locked
cargo nextest run -p agenc-relay-storage --test stage_five --locked e2ee_records
cargo nextest run -p agenc-relay-runtime --lib e2ee:: --locked
cargo nextest run -p agenc-relay-runtime --lib registration::tests --locked
cargo nextest run -p agenc-relay-testkit --test mls_interop --locked
cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --locked

echo "stage-eight transcript catalog: ok"
