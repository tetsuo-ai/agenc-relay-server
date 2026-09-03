#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p agenc-ircd-federation-wire --test text_carrier --locked
cargo test -p agenc-ircd-domain --lib federation:: --locked
cargo test -p agenc-ircd-storage --test stage_five --locked federation_records
cargo test -p agenc-ircd-runtime --test federation_link --locked
cargo test -p agenc-ircd-runtime --lib federation:: --locked
cargo test -p agenc-ircd-runtime --lib admin::tests::federation_commands_record_intent_and_outcome --locked
cargo test -p agenc-ircd --test stage_seven_federation --locked

echo "stage-seven transcript catalog: ok"
