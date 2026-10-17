#!/usr/bin/env bash
# Tests for the mutation-test scripts and the rules of the workflow that
# runs them (.github/workflows/mutants.yml). Needs bash, git and coreutils,
# not Rust: a stand-in cargo plays the tests.
#
# Usage: .github/mutants/test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
pass() {
  echo "ok: $*"
}

# --- summary.sh ---------------------------------------------------------

# shard <reports> <name> <done?> <"outcome name"...>
shard() {
  local dir=$1/$2 finished=$3
  shift 3
  mkdir -p "$dir"
  : > "$dir/results.tsv"
  local line
  for line in "$@"; do printf '%s\t%s\n' "${line%% *}" "${line#* }" >> "$dir/results.tsv"; done
  if [ "$finished" = yes ]; then touch "$dir/done"; fi
}

summary() { # <reports> <shards>: the status, with the output in $work/summary.out
  local status=0
  bash "$here/summary.sh" "$1" "$2" > "$work/summary.out" 2>&1 || status=$?
  echo "$status"
}

t=$work/all-caught
shard "$t" linux-0 yes "caught a.rs:1:1: replace f with g" "unviable a.rs:2:1: replace h with i"
shard "$t" windows-0 yes "missed a.rs:1:1: replace f with g" "caught patch keep-attr"
if [ "$(summary "$t" 2)" = 0 ] && grep -q '| cargo-mutants | 1 | 0 | 0 | 1 |' "$work/summary.out" &&
  grep -q '| Hand-made | 1 | 0 | 0 | 0 |' "$work/summary.out"; then
  pass "a mutant caught on one OS counts as caught, and the run passes"
else
  fail "a mutant caught on one OS should count as caught"; cat "$work/summary.out"
fi

t=$work/missed
shard "$t" linux-0 yes "missed a.rs:1:1: replace f with g" "unviable a.rs:1:1: replace f with g"
shard "$t" windows-0 yes "unviable a.rs:1:1: replace f with g"
if [ "$(summary "$t" 2)" = 1 ] && grep -q '| cargo-mutants | 0 | 1 | 0 | 0 |' "$work/summary.out" &&
  grep -qF -- '- `a.rs:1:1: replace f with g`' "$work/summary.out"; then
  pass "a missed mutant fails the run and is named"
else
  fail "a missed mutant should fail the run"; cat "$work/summary.out"
fi

t=$work/missed-patch
shard "$t" linux-0 yes "missed patch keep-attr"
if [ "$(summary "$t" 1)" = 1 ] && grep -q '| Hand-made | 0 | 1 | 0 | 0 |' "$work/summary.out"; then
  pass "a missed hand-made mutation fails the run"
else
  fail "a missed hand-made mutation should fail the run"; cat "$work/summary.out"
fi

t=$work/timeout
shard "$t" linux-0 yes "timeout a.rs:1:1: replace f with g"
if [ "$(summary "$t" 1)" = 1 ] && grep -q '| cargo-mutants | 0 | 0 | 1 | 0 |' "$work/summary.out" &&
  grep -qF -- '- `a.rs:1:1: replace f with g`' "$work/summary.out"; then
  pass "a mutant that only timed out fails the run and is named"
else
  fail "a mutant that only timed out should fail the run"; cat "$work/summary.out"
fi

# The proof run's set-tunnel mutant: missed on Linux, timed out on Windows.
t=$work/missed-and-timeout
shard "$t" linux-0 yes "missed a.rs:1:1: replace f with g" "missed a.rs:1:1: replace f with g"
shard "$t" windows-0 yes "missed a.rs:1:1: replace f with g" "timeout a.rs:1:1: replace f with g"
if [ "$(summary "$t" 2)" = 1 ] && grep -q '| cargo-mutants | 0 | 1 | 0 | 0 |' "$work/summary.out"; then
  pass "a mutant missed on one OS and timed out on the other counts as missed"
else
  fail "a miss must not be hidden by a timeout elsewhere"; cat "$work/summary.out"
fi

t=$work/caught-and-timeout
shard "$t" linux-0 yes "caught a.rs:1:1: replace f with g"
shard "$t" windows-0 yes "timeout a.rs:1:1: replace f with g"
if [ "$(summary "$t" 2)" = 0 ] && grep -q '| cargo-mutants | 1 | 0 | 0 | 0 |' "$work/summary.out"; then
  pass "a mutant caught on one OS and timed out on the other counts as caught"
else
  fail "a catch on one OS should count over a timeout on the other"; cat "$work/summary.out"
fi

t=$work/unviable-patch
shard "$t" linux-0 yes "caught patch keep-attr" "unviable patch broken-patch"
if [ "$(summary "$t" 1)" = 1 ] && grep -qF -- '- `patch broken-patch`' "$work/summary.out"; then
  pass "a hand-made mutation that does not build fails the run and is named"
else
  fail "a hand-made mutation that does not build should fail the run"; cat "$work/summary.out"
fi

t=$work/unfinished
shard "$t" linux-0 yes "caught a.rs:1:1: replace f with g"
shard "$t" linux-1 no "caught a.rs:2:1: replace f with g"
if [ "$(summary "$t" 2)" = 1 ] && grep -q "did not finish" "$work/summary.out"; then
  pass "a shard that did not finish fails the run"
else
  fail "a shard that did not finish should fail the run"; cat "$work/summary.out"
fi

t=$work/lost
shard "$t" linux-0 yes "caught a.rs:1:1: replace f with g"
if [ "$(summary "$t" 2)" = 1 ] && grep -q "Expected 2 shards' results, found 1" "$work/summary.out"; then
  pass "a shard whose results are missing fails the run"
else
  fail "a missing shard should fail the run"; cat "$work/summary.out"
fi

t=$work/garbled
shard "$t" linux-0 yes "found a.rs:1:1: replace f with g"
if [ "$(summary "$t" 1)" = 1 ]; then
  pass "an outcome it does not know fails the run"
else
  fail "an unknown outcome should fail the run"; cat "$work/summary.out"
fi

# --- patches.sh ---------------------------------------------------------

# A repository whose "tests" are a stand-in cargo: they fail when rule.txt
# no longer says "strict", hang when it says "hang", do not build when
# build.txt says "broken", and rewrite generated.txt each time they run.
repo=$work/repo
mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config user.name test
git -C "$repo" config user.email test@example.test
git -C "$repo" config core.autocrlf false
printf 'strict\n' > "$repo/rule.txt"
printf 'fine\n' > "$repo/build.txt"
printf 'notes\n' > "$repo/notes.txt"
printf 'generated\n' > "$repo/generated.txt"
git -C "$repo" add .
git -C "$repo" commit -q -m initial

cat > "$work/cargo" << 'EOF'
#!/usr/bin/env bash
[ "$1" = test ] && [ "$2" = --locked ] || { echo "stand-in cargo: unexpected $*" >&2; exit 64; }
echo "$*" >> "$CALLS"
if [ "${3:-}" = --no-run ]; then
  ! grep -q broken build.txt
  exit
fi
echo "rewritten by $*" > generated.txt
if grep -q hang rule.txt; then sleep 30; fi
grep -qx strict rule.txt
EOF
chmod +x "$work/cargo"

# mutation <id> <os> <file> <from> <to>: a header and a patch.
mutation() {
  local id=$1 where=$2 file=$3 from=$4 to=$5
  printf '=== mutation: %s\n=== os: %s\n=== test: -p example --lib\n' "$id" "$where"
  printf 'diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n-%s\n+%s\n' \
    "$file" "$file" "$file" "$file" "$from" "$to"
}

patches() { # <file> <shard> <shards> <out> [os]: the status
  local status=0
  (cd "$repo" && CALLS=$work/calls MUTANTS_OS=${5:-linux} MUTANTS_CARGO=$work/cargo MUTANTS_TIMEOUT=2 \
    bash "$here/patches.sh" "$1" "$2" "$3" "$4") > "$work/patches.out" 2>&1 || status=$?
  echo "$status"
}

untouched() {
  [ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ] &&
    [ "$(cat "$repo/rule.txt")" = strict ] && [ "$(cat "$repo/generated.txt")" = generated ]
}

{
  echo "Hand-made mutations for the tests."
  mutation loosen all rule.txt strict lax
  mutation notes all notes.txt notes jottings
  mutation break-build all build.txt fine broken
  mutation hang all rule.txt strict hang
  mutation windows-only windows rule.txt strict lax
} > "$work/mutations"

out=$work/out-all
: > "$work/calls"
if [ "$(patches "$work/mutations" 0 1 "$out")" = 0 ]; then
  expected=$'caught\tpatch loosen\nmissed\tpatch notes\nunviable\tpatch break-build\ntimeout\tpatch hang'
  if [ "$(cat "$out/results.tsv")" = "$expected" ]; then
    pass "each mutation is caught, missed, unviable or timed out, as its tests say"
  else
    fail "unexpected outcomes:"; cat "$out/results.tsv"
  fi
else
  fail "patches.sh failed"; cat "$work/patches.out"
fi
if untouched; then
  pass "each patch is taken out after its run, with what the tests rewrote"
else
  fail "the checkout was left changed"; git -C "$repo" status --short
fi
if grep -q "windows-only" "$out/results.tsv"; then
  fail "a mutation for Windows ran on Linux"
else
  pass "a mutation for another OS does not run"
fi

out=$work/out-windows
if [ "$(patches "$work/mutations" 0 1 "$out" windows)" = 0 ] && grep -q $'^caught\tpatch windows-only$' "$out/results.tsv"; then
  pass "a mutation for Windows runs on Windows"
else
  fail "the Windows mutation did not run on Windows"; cat "$work/patches.out"
fi

out0=$work/out-shard0 out1=$work/out-shard1
patches "$work/mutations" 0 2 "$out0" > /dev/null
patches "$work/mutations" 1 2 "$out1" > /dev/null
if [ "$(cut -f 2 "$out0/results.tsv" | tr '\n' ' ')" = "patch loosen patch break-build " ] &&
  [ "$(cut -f 2 "$out1/results.tsv" | tr '\n' ' ')" = "patch notes patch hang " ]; then
  pass "the mutations are shared out among the shards"
else
  fail "the shards did not share the mutations"; cat "$out0/results.tsv" "$out1/results.tsv"
fi

{
  echo "=== mutation: stale"
  echo "=== os: all"
  echo "=== test: -p example"
  printf 'diff --git a/rule.txt b/rule.txt\n--- a/rule.txt\n+++ b/rule.txt\n@@ -1 +1 @@\n-gone\n+lax\n'
} > "$work/stale"
if [ "$(patches "$work/stale" 0 1 "$work/out-stale")" != 0 ] && grep -q "does not apply" "$work/patches.out" && untouched; then
  pass "a patch that does not apply fails the run"
else
  fail "a patch that does not apply should fail the run"; cat "$work/patches.out"
fi

printf 'lax\n' > "$repo/rule.txt"
git -C "$repo" commit -q -am "tests fail"
mutation notes all notes.txt notes jottings > "$work/notes"
if [ "$(patches "$work/notes" 0 1 "$work/out-failing")" != 0 ] && grep -q "fail without it" "$work/patches.out"; then
  pass "a mutation whose tests fail without it fails the run"
else
  fail "tests that fail without the mutation should fail the run"; cat "$work/patches.out"
fi
git -C "$repo" reset -q --hard HEAD~1

printf 'changed\n' > "$repo/notes.txt"
if [ "$(patches "$work/notes" 0 1 "$work/out-dirty")" != 0 ] && grep -q "has changes before" "$work/patches.out"; then
  pass "a checkout with changes is refused"
else
  fail "a checkout with changes should be refused"; cat "$work/patches.out"
fi
git -C "$repo" checkout -q -- notes.txt

# Each of these must be refused for its own reason, and leave the checkout
# as it was. <reason> <file content>
cases=0
refuse() {
  cases=$((cases + 1))
  printf '%s\n' "$2" > "$work/bad"
  if [ "$(patches "$work/bad" 0 1 "$work/out-bad-$cases")" != 0 ] && grep -qF -- "$1" "$work/patches.out"; then
    pass "refused: $1"
  else
    fail "a malformed file of mutations was not refused with '$1':"
    cat "$work/bad" "$work/patches.out"
  fi
}
good=$(mutation x all notes.txt notes a)
body=$(printf '%s\n' "$good" | tail -n +4)
refuse "is not letters, digits" "$(mutation 'two words' all notes.txt notes a)"
refuse "the os must be all, linux or windows" "$(mutation x mac notes.txt notes a)"
refuse "plain words separated by single spaces" \
  "$(printf '=== mutation: x\n=== os: all\n=== test: -p x; rm -rf /\n%s' "$body")"
refuse 'expected "=== os: "' "$(printf '=== mutation: x\n=== test: -p x\n%s' "$body")"
refuse "the last mutation has no patch" $'=== mutation: x\n=== os: all\n=== test: -p x'
refuse "the mutation before this one has no patch" \
  "$(printf '=== mutation: x\n=== os: all\n=== test: -p x\n%s' "$(mutation y all notes.txt notes a)")"
refuse "a header line inside a patch" "$(printf '%s\n=== os: all' "$good")"
refuse "is used twice" "$(mutation same all notes.txt notes a; mutation same all rule.txt strict b)"
refuse "no mutations in the file" "nothing but a comment"
if untouched; then
  pass "a refused file leaves the checkout as it was"
else
  fail "a refused file changed the checkout"
fi

# --- every cargo goes through cargo.sh ----------------------------------

# On Windows only cargo.sh gives the tests the workflow's token defaults
# (token.ps1), without which the elevated tests fail or, worse, pass for the
# wrong reason.
if grep -hnE '(^|[^.[:alnum:]_/-])cargo +(mutants|test|build)' "$here/shard.sh" "$here/patches.sh" |
  grep -vE '^[0-9]+: *#' | grep -v 'cargo\.sh'; then
  fail "shard.sh and patches.sh must start cargo only through cargo.sh"
else
  pass "every cargo goes through cargo.sh"
fi

# --- the workflow -------------------------------------------------------

workflow=$root/.github/workflows/mutants.yml
# The whole workflow has a read-only token and no job asks for more.
if [ "$(sed -n '/^permissions:$/,/^[^ ]/{/^  /p;}' "$workflow")" = "  contents: read" ] &&
  [ "$(grep -c 'permissions:' "$workflow")" = 1 ]; then
  pass "the token can only read the repository"
else
  fail "mutants.yml must have exactly 'permissions: contents: read' at the top"
fi
checkouts=$(grep -c 'uses: actions/checkout@' "$workflow")
if [ "$checkouts" -gt 0 ] && [ "$(grep -c 'persist-credentials: false' "$workflow")" = "$checkouts" ]; then
  pass "no checkout keeps the token"
else
  fail "every checkout in mutants.yml must set persist-credentials: false"
fi
if grep -nE 'secrets\.|git (commit|push)|gh (pr|api|release)|: write' "$workflow"; then
  fail "mutants.yml must use no secrets and must not commit, push or write"
else
  pass "no secrets, commits or pushes"
fi
if [ "$(sed -n '/^on:$/,/^[^ ]/{/^  [a-z_]*:/p;}' "$workflow")" = "  workflow_dispatch:" ]; then
  pass "started by hand only"
else
  fail "mutants.yml must be started by hand only"
fi
if [ "$(grep -c '^    timeout-minutes:' "$workflow")" = "$(grep -c '^    runs-on:' "$workflow")" ]; then
  pass "every job has a time limit"
else
  fail "every job in mutants.yml needs timeout-minutes"
fi
# A missed mutant fails the run: the summary runs whatever happened before
# and its failure is the run's.
if sed -n '/^  summary:$/,$p' "$workflow" | grep -q '^    if: always()$' &&
  ! sed -n '/^  summary:$/,$p' "$workflow" | grep -q 'continue-on-error'; then
  pass "the summary always runs and can fail the run"
else
  fail "the summary job must run always() and never continue on error"
fi

# Only a scratch branch may start it: the first step of the first job
# refuses any other ref, before anything is checked out, and every other job
# that checks out the pull request needs that job.
prepare=$(sed -n '/^  prepare:$/,/^  [a-z]*:$/p' "$workflow")
first_step=$(awk '/^    steps:$/ { on = 1; next } on && /^      - / { n++ } on && n == 1' <<< "$prepare")
if grep -qF 'if [[ $GITHUB_REF != refs/heads/test/mut-* ]]; then' <<< "$first_step" &&
  grep -q 'exit 1' <<< "$first_step" && ! grep -q 'uses:' <<< "$first_step" &&
  [ "$(sed -n '/^  mutants:$/,/^  [a-z]*:$/p' "$workflow" | grep -c '^    needs: prepare$')" = 1 ]; then
  pass "only a test/mut-* branch can start it"
else
  fail "mutants.yml must refuse, in prepare's first step, any ref but refs/heads/test/mut-*"
fi

# A timeout is not a catch: only caught.txt takes a mutant out of the later
# runs, and the runs over the whole workspace get a longer test time limit.
if grep -B 1 'grep -vxF -f - "$remaining"' "$here/shard.sh" | grep -q 'caught.txt' &&
  ! grep -B 1 'grep -vxF -f - "$remaining"' "$here/shard.sh" | grep -q 'timeout.txt' &&
  [ "$(grep -F -- '--test-workspace=true' "$here/shard.sh" | grep -cF '"${slow[@]}"')" = 2 ] &&
  [ "$(grep -cF -- '--test-workspace=true' "$here/shard.sh")" = 2 ] &&
  grep -q '^slow=(--minimum-test-timeout=[0-9]*)$' "$here/shard.sh"; then
  pass "timed-out mutants go on to the later runs, and workspace runs have a longer limit"
else
  fail "shard.sh must drop only caught mutants and give workspace runs a minimum test timeout"
fi

# shard.sh checks the tracked files match the commit before it starts and
# after every cargo-mutants run, so no mutation is left in place.
if [ "$(grep -c '^  if ! clean; then$' "$here/shard.sh")" = 1 ] && [ "$(grep -c '^if ! clean; then$' "$here/shard.sh")" = 1 ] &&
  grep -q 'git status --porcelain --untracked-files=no' "$here/shard.sh"; then
  pass "shard.sh checks the checkout before and after each run"
else
  fail "shard.sh must check the checkout matches its commit before and after each run"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures failed." >&2
  exit 1
fi
echo "All passed."
