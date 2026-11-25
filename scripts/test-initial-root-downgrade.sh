#!/usr/bin/env bash
# Build the last base-profile daemon separately, then exercise its storage admission.
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
revision=055b2517fa7247c1d1d32281dd03f36fc69b3c5b
case_name=initial_root_downgrade::previous_daemon_accepts_legacy_and_refuses_the_last_guarded_account_format_fence
scratch=$(mktemp -d "${TMPDIR:-/tmp}/initial-root-downgrade.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
mkdir -- "$scratch/previous"
git -C "$root" archive "$revision" | tar -xf - -C "$scratch/previous"
(
  cd -- "$scratch/previous"
  CARGO_TARGET_DIR="$scratch/old-target" cargo build --locked -p agenc-relay-server --bin arcd
)
cd -- "$root"
ARC_INITIAL_ROOT_PREVIOUS_ARCD="$scratch/old-target/debug/arcd" \
  cargo test --locked -p agenc-relay-server --test stage_eight_e2ee "$case_name" \
    -- --exact --ignored --nocapture | tee "$scratch/result"
grep -Fxq "test $case_name ... ok" "$scratch/result"
