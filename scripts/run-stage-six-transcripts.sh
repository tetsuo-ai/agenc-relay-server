#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-ircd-admin --locked
cargo test -p agenc-ircd-client-wire --test registration_command --locked
cargo test -p agenc-ircd-runtime --test listener_accept --test tls_endpoint --locked
cargo test -p agenc-ircd-runtime --lib admin::tests --locked

echo "stage-six transcript catalog: ok"
