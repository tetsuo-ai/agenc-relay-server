#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo nextest run -p agenc-relay-federation-wire --test text_carrier --locked
cargo nextest run -p agenc-relay-domain --lib federation:: --locked
cargo nextest run -p agenc-relay-storage --test stage_five --locked federation_records
cargo nextest run -p agenc-relay-runtime --test federation_link --locked
cargo nextest run -p agenc-relay-runtime --lib federation:: --locked
cargo nextest run -p agenc-relay-runtime --lib admin::tests::federation_commands_record_intent_and_outcome --locked
cargo nextest run -p agenc-relay-server --test stage_seven_federation --locked

echo "stage-seven transcript catalog: ok"
