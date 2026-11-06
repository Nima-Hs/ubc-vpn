#!/usr/bin/env bash
# Scratch only: does the logon test hold when run again, and why not.
set -uo pipefail
for n in 1 2 3; do
  echo "=== run $n"
  cargo test --locked -p ubc-vpn-platform --features secrets --lib -- secrets::credentials::tests::real_across_new_logons --nocapture 2>&1 | grep -vE '^\s*(Compiling|Finished|Running)' | tail -60
done
perl -0pi -e "s/match target\.contains\('\\0'\)/match false/" crates/platform/src/windows/credentials.rs
git diff --stat
echo "=== with nul-allowed"
cargo test --locked -p ubc-vpn-platform --features secrets --lib -- secrets::credentials::tests::real_across_new_logons --nocapture 2>&1 | tail -80
git checkout -q -- crates/platform/src/windows/credentials.rs
