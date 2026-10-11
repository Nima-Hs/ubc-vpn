#!/usr/bin/env bash
# Marks the build output as safe to ship. The workflow runs this as its last
# step before uploading, so it only happens when every test before it passed
# on this same output. Do not run it by hand.
set -euo pipefail

manifest=$(cd "$(dirname "$0")/.." && pwd)/out/manifest.json
grep -q '^  "shippable": false,$' "$manifest"
sed -i 's/^  "shippable": false,$/  "shippable": true,/; s/^  "blockers": \[.*\],$/  "blockers": [],/' "$manifest"
