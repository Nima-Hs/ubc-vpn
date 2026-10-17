#!/usr/bin/env bash
# Adds up the shards' results and fails unless every mutant was caught or
# could not be built, and every hand-made mutation was caught.
#
# Usage: summary.sh <reports> <shards>
#
# <reports> holds one folder per shard and OS, each with the results.tsv
# that shard.sh and patches.sh wrote and the `done` that run.sh writes once
# both finished. <shards> is how many such folders there must be.
#
# A mutant is tested on each OS, and possibly more than once on each. It
# counts as caught if any run caught it; failing that, as missed if any run
# missed it; failing that, as a timeout if any run timed out; and otherwise
# as unviable. A timeout is never taken for a catch: a slow suite runs out of
# time too. So a mutant that only timed out fails the run like a missed one,
# and a miss anywhere is never hidden by a timeout elsewhere. A hand-made
# mutation that does not build fails the run as well: its patch is wrong.
# Written to standard output and, when GITHUB_STEP_SUMMARY
# names a file, to that file too.
set -euo pipefail

if [ "$#" -ne 2 ] || ! [[ $2 =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: summary.sh <reports> <shards>" >&2
  exit 2
fi
reports=$1 shards=$2

failed=0
found=0
for dir in "$reports"/*/; do
  [ -d "$dir" ] || continue
  found=$((found + 1))
  if ! [ -f "$dir/done" ] || ! [ -f "$dir/results.tsv" ]; then
    echo "The shard in $dir did not finish." >&2
    failed=1
  fi
done
if [ "$found" -ne "$shards" ]; then
  echo "Expected $shards shards' results, found $found." >&2
  failed=1
fi

merged=$(mktemp)
cat "$reports"/*/results.tsv 2> /dev/null |
  awk -F '\t' '
    BEGIN { rank["unviable"] = 1; rank["timeout"] = 2; rank["missed"] = 3; rank["caught"] = 4 }
    NF != 2 || !($1 in rank) { print "A results line is not as expected: " $0 > "/dev/stderr"; bad = 1; next }
    !($2 in best) || rank[$1] > rank[best[$2]] { best[$2] = $1 }
    END { for (name in best) print best[name] "\t" name; exit bad }
  ' | LC_ALL=C sort -t "$(printf '\t')" -k 2 > "$merged" || failed=1

count() { # <outcome> <mutants|patches>
  if [ "$2" = mutants ]; then
    awk -F '\t' -v o="$1" '$1 == o && $2 !~ /^patch / { n++ } END { print n + 0 }' "$merged"
  else
    awk -F '\t' -v o="$1" '$1 == o && $2 ~ /^patch / { n++ } END { print n + 0 }' "$merged"
  fi
}

# True if some mutant has this outcome.
has() {
  awk -F '\t' -v o="$1" '$1 == o { found = 1 } END { exit !found }' "$merged"
}

{
  echo "## Mutation tests"
  echo
  echo "| | Caught | Missed | Timeout | Unviable |"
  echo "| --- | ---: | ---: | ---: | ---: |"
  for kind in mutants patches; do
    label="cargo-mutants"
    if [ "$kind" = patches ]; then label="Hand-made"; fi
    echo "| $label | $(count caught "$kind") | $(count missed "$kind") | $(count timeout "$kind") | $(count unviable "$kind") |"
  done
  # Unviable ones are listed only for hand-made mutations.
  for outcome in missed timeout unviable; do
    listed=$(awk -F '\t' -v o="$outcome" '$1 == o && (o != "unviable" || $2 ~ /^patch /) { print "- `" $2 "`" }' "$merged")
    if [ -n "$listed" ]; then
      echo
      echo "### ${outcome^}"
      echo
      echo "$listed"
    fi
  done
  if [ "$failed" -ne 0 ]; then
    echo
    echo "Some shards did not finish, so these numbers are not the whole result."
  fi
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

if has missed; then
  echo "Some mutants were missed: no test failed with them." >&2
  failed=1
fi
if has timeout; then
  echo "Some mutants only timed out, and a timeout is not a catch: no test failed with them." >&2
  failed=1
fi
if [ "$(count unviable patches)" -ne 0 ]; then
  echo "Some hand-made mutations do not build: their patches need fixing." >&2
  failed=1
fi
rm -f "$merged"
exit "$failed"
