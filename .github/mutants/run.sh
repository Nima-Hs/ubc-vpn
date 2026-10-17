#!/usr/bin/env bash
# One shard of the mutation tests: cargo-mutants over the pull request's
# diff, then the hand-made mutations, if a file of them is named. The
# working directory is a throwaway checkout of the pull request's head.
#
# Usage: run.sh <diff> <shard> <shards> <out> [<file of mutations>]
#
# Writes <out>/done last, so the summary can tell a shard that finished.
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  echo "Usage: run.sh <diff> <shard> <shards> <out> [<file of mutations>]" >&2
  exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
diff=$1 shard=$2 shards=$3 out=$4 patches=${5:-}

bash "$here/shard.sh" "$diff" "$shard" "$shards" "$out"
if [ -n "$patches" ]; then
  bash "$here/patches.sh" "$patches" "$shard" "$shards" "$out"
fi
touch "$out/done"
