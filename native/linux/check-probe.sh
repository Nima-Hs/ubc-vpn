#!/usr/bin/env bash
# Runs a probe command and requires both the expected library version and
# RESULT: PASS. Usage: check-probe.sh <version> <command...>
set -euo pipefail

version=$1
shift
log=$(mktemp)
"$@" | tee "$log"
grep -qx "version  = $version" "$log" || { echo "error: the probe did not load $version" >&2; exit 1; }
grep -qE '^setup_tun_fd = 0x[0-9a-f]+$' "$log"
grep -qx "RESULT: PASS" "$log"
