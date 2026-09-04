#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-ircd-e2ee --all-features --locked
cargo test -p agenc-ircd-domain --lib e2ee:: --locked
cargo test -p agenc-ircd-storage --test stage_five --locked e2ee_records
cargo test -p agenc-ircd-runtime --lib e2ee:: --locked
cargo test -p agenc-ircd-runtime --lib registration::tests --locked
cargo test -p agenc-ircd-testkit --test mls_interop --locked
cargo test -p agenc-ircd --test stage_eight_e2ee --locked

echo "stage-eight transcript catalog: ok"
