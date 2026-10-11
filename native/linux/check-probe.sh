#!/usr/bin/env bash
# Runs a probe command and requires both the expected library version and
# RESULT: PASS. Usage: check-probe.sh <version> <command...>
set -euo pipefail

version=$1
shift
log=$(mktemp)
"$@" | tee "$log"
grep -qx "version  = $version" "$log" || { echo "error: the probe did not load $version" >&2; exit 1; }
grep -qx "RESULT: PASS" "$log"
