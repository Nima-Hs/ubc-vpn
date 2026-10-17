#!/usr/bin/env bash
# Runs hand-made mutations: the changes cargo-mutants cannot make, such as
# taking away an attribute (`#[serde(deny_unknown_fields)]`) or a `cfg`
# (`#[cfg(debug_assertions)]`). The working directory is a throwaway
# checkout of the pull request's head. Nothing is committed or pushed.
#
# Usage: patches.sh <file> <shard> <shards> <out>
#
# The file holds one or more mutations. Each starts with three header lines
# and goes on with the patch that makes the one change, as `git diff`
# writes it, relative to the repository's root:
#
#   === mutation: <id>
#   === os: all | linux | windows
#   === test: <arguments for cargo test>
#   diff --git a/crates/core/src/x.rs b/crates/core/src/x.rs
#   ...
#
# Lines before the first header are a comment. The id is letters, digits,
# `.`, `_` and `-`. The test arguments are words separated by single spaces,
# with no quoting, run as `cargo test --locked <arguments>`.
#
# The mutations for this OS are shared out among the shards in order. For
# each one in this shard, the tests must pass without it and its patch must
# apply. If it then does not build, it is unviable. Otherwise the tests run
# with it: one failing means it was caught, all passing means it was missed.
# Its patch is then taken out again, and the tracked files must match the
# commit checked out. Once all have run, each test must still pass.
#
# <out>/results.tsv gets one line for each mutation: the outcome, a tab, and
# `patch <id>`. MUTANTS_CARGO names the cargo to run (for this script's own
# tests) and MUTANTS_TIMEOUT the seconds a test run may take.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "Usage: patches.sh <file> <shard> <shards> <out>" >&2
  exit 2
fi
file=$1 shard=$2 shards=$3 out=$4
os=${MUTANTS_OS:-}
cargo=${MUTANTS_CARGO:-cargo}
limit=${MUTANTS_TIMEOUT:-1800}
case $os in
  linux | windows) ;;
  *) echo "MUTANTS_OS must be linux or windows." >&2; exit 2 ;;
esac
if ! [[ $shard =~ ^[0-9]+$ && $shards =~ ^[1-9][0-9]*$ ]] || [ "$shard" -ge "$shards" ]; then
  echo "The shard must be a number below the number of shards." >&2
  exit 2
fi
if ! [ -f "$file" ]; then
  echo "There is no file of mutations at $file." >&2
  exit 1
fi

work=$out/patches
mkdir -p "$work"
touch "$out/results.tsv"

# Split the file into <n>.meta (id, os, test, each on a line) and <n>.patch.
awk -v dir="$work" '
  function fail(message) { print FILENAME ":" FNR ": " message > "/dev/stderr"; bad = 1; exit 1 }
  /^=== mutation: / {
    if (n > 0 && lines == 0) fail("the mutation before this one has no patch")
    n++; state = 1; lines = 0
    print substr($0, 15) > (dir "/" n ".meta")
    next
  }
  state == 1 {
    if ($0 !~ /^=== os: /) fail("expected \"=== os: \"")
    print substr($0, 9) > (dir "/" n ".meta"); state = 2; next
  }
  state == 2 {
    if ($0 !~ /^=== test: /) fail("expected \"=== test: \"")
    print substr($0, 11) > (dir "/" n ".meta"); state = 3; next
  }
  state == 3 {
    if ($0 ~ /^=== /) fail("a header line inside a patch")
    print > (dir "/" n ".patch"); lines++
  }
  END {
    if (bad) exit 1
    if (n == 0) { print FILENAME ": no mutations in the file" > "/dev/stderr"; exit 1 }
    if (state != 3 || lines == 0) { print FILENAME ": the last mutation has no patch" > "/dev/stderr"; exit 1 }
    print n > (dir "/count")
  }
' "$file"

count=$(cat "$work/count")
ids=()
mine=()
index=0
for n in $(seq 1 "$count"); do
  { IFS= read -r id; IFS= read -r where; IFS= read -r test; } < "$work/$n.meta"
  if ! [[ $id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "Mutation $n: the id '$id' is not letters, digits, '.', '_' and '-'." >&2
    exit 1
  fi
  for seen in "${ids[@]}"; do
    if [ "$seen" = "$id" ]; then
      echo "Mutation $n: the id '$id' is used twice." >&2
      exit 1
    fi
  done
  ids+=("$id")
  case $where in
    all | linux | windows) ;;
    *) echo "Mutation $id: the os must be all, linux or windows." >&2; exit 1 ;;
  esac
  if ! [[ $test =~ ^[A-Za-z0-9_:./=,+-]+( [A-Za-z0-9_:./=,+-]+)*$ ]]; then
    echo "Mutation $id: the test arguments must be plain words separated by single spaces." >&2
    exit 1
  fi
  if [ "$where" = all ] || [ "$where" = "$os" ]; then
    if [ $((index % shards)) -eq "$shard" ]; then mine+=("$n"); fi
    index=$((index + 1))
  fi
done
echo "$count mutations in $file, $index for $os, ${#mine[@]} of them in shard $shard of $shards."

head=$(git rev-parse HEAD)
clean() {
  [ -z "$(git status --porcelain --untracked-files=no)" ] && [ "$(git rev-parse HEAD)" = "$head" ]
}
if ! clean; then
  echo "The checkout has changes before any mutation is applied." >&2
  exit 1
fi

# Runs the tests named by a mutation, with a time limit. Status 124 is a
# timeout.
tests() {
  local args
  read -ra args <<< "$1"
  timeout "$limit" "$cargo" test --locked "${args[@]}"
}

declare -A passed=()
for n in "${mine[@]}"; do
  { IFS= read -r id; IFS= read -r where; IFS= read -r test; } < "$work/$n.meta"
  patch=$work/$n.patch
  echo "::group::Mutation $id: the tests pass without it"
  if [ -z "${passed[$test]:-}" ]; then
    if ! tests "$test"; then
      echo "::endgroup::"
      echo "Mutation $id: the tests fail without it, so it proves nothing." >&2
      exit 1
    fi
    passed[$test]=1
  fi
  echo "::endgroup::"
  # Each mutation starts from the commit, not from what the tests rewrote.
  git checkout HEAD -- .
  if ! git apply --check "$patch"; then
    echo "Mutation $id: its patch does not apply to the pull request's head." >&2
    exit 1
  fi
  git apply "$patch"
  echo "::group::Mutation $id: applied, building and testing"
  git --no-pager diff --stat
  status=0
  args=()
  read -ra args <<< "$test"
  if ! "$cargo" test --locked --no-run "${args[@]}"; then
    outcome=unviable
  else
    tests "$test" || status=$?
    case $status in
      0) outcome=missed ;;
      124) outcome=timeout ;;
      *) outcome=caught ;;
    esac
  fi
  echo "::endgroup::"
  # Take the patch out, then anything the tests rewrote, such as the
  # generated TypeScript types.
  if ! git apply -R "$patch"; then
    echo "Mutation $id: its patch could not be taken out again." >&2
    exit 1
  fi
  git checkout HEAD -- .
  if ! clean; then
    echo "Mutation $id: the checkout does not match its commit after the patch was taken out." >&2
    git status --short --untracked-files=no >&2
    exit 1
  fi
  printf '%s\tpatch %s\n' "$outcome" "$id" >> "$out/results.tsv"
  echo "Mutation $id: $outcome."
done

# A mutation that left the machine broken must not pass for caught.
for test in "${!passed[@]}"; do
  echo "::group::The tests pass after the mutations: $test"
  if ! tests "$test"; then
    echo "::endgroup::"
    echo "The tests '$test' fail after the mutations: their results cannot be trusted." >&2
    exit 1
  fi
  echo "::endgroup::"
done
git checkout HEAD -- .
