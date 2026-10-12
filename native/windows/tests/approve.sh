#!/usr/bin/env bash
# Marks the build output as safe to ship. The workflow runs this as its last
# step before uploading, so it only happens when every test before it passed
# on this same output. Do not run it by hand.
#
# An output whose GnuTLS was reused from an earlier run stays unshippable: its
# DLL was not built from the pinned source in this run, and nothing here can
# check that it ever was.
set -euo pipefail

# seal.sh passes a copy of the manifest, to learn what this will make of it.
manifest=${1:-$(cd "$(dirname "$0")/.." && pwd)/out/manifest.json}
grep -q '^  "shippable": false,$' "$manifest"

# An output that cannot name the commit of this repository it was built from
# cannot be traced back to a reviewed recipe, so it is never shippable.
if ! grep -q -E '^    "commit": "[0-9a-f]{40}",$' "$manifest"; then
    echo "error: recipe.commit in the manifest is not a commit id; refusing to mark the output shippable" >&2
    exit 1
fi

if grep -q '^      "built_in_this_run": true,$' "$manifest"; then
    sed -i 's/^  "shippable": false,$/  "shippable": true,/; s/^  "blockers": \[.*\],$/  "blockers": [],/' "$manifest"
    echo "marked shippable"
else
    sed -i 's/^  "blockers": \[.*\],$/  "blockers": ["GnuTLS was reused from an earlier build, not built in this run."],/' "$manifest"
    echo "not marked shippable: GnuTLS was reused from an earlier build"
fi
