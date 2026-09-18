#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo nextest run -p agenc-ircd-admin --locked
cargo nextest run -p agenc-ircd-client-wire --test registration_command --locked
cargo nextest run -p agenc-ircd-runtime --test listener_accept --test tls_endpoint --test tor_client --locked
cargo nextest run -p agenc-ircd-runtime --lib admin::tests --locked
cargo nextest run -p agenc-ircd --test stage_six_daemon --locked

echo "stage-six transcript catalog: ok"
