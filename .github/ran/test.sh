#!/usr/bin/env bash
# Tests for check.sh, and that every list in .github/ran is well formed.
# Needs only bash and coreutils; runs on macOS's bash 3.2 as well.
#
# Usage: .github/ran/test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
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

check() { # <folder> <prefix> <log>: the status, with the output in $work/out
  local status=0
  bash "$here/check.sh" "$@" > "$work/out" 2>&1 || status=$?
  echo "$status"
}

lists=$work/lists
mkdir -p "$lists"
printf '%s\n' "full tunnel" "dns" > "$lists/a.txt"
printf '%s\n' "events" > "$lists/b.txt"
printf '%s\n' "RAN: full tunnel" "RAN: dns" "RAN: events" "other output" > "$work/all.log"

if [ "$(check "$lists" "RAN: " "$work/all.log")" = 0 ] && grep -q "All 3 tests in 2 lists" "$work/out"; then
  pass "every name in every list ran"
else
  fail "a log with every name should pass"; cat "$work/out"
fi

printf '%s\n' "RAN: full tunnel foreign" "RAN: dns" "RAN: events" > "$work/near.log"
if [ "$(check "$lists" "RAN: " "$work/near.log")" = 1 ] &&
  grep -qF "The test 'full tunnel' ($lists/a.txt) did not run" "$work/out"; then
  pass "a name must match a whole line"
else
  fail "'full tunnel foreign' must not satisfy 'full tunnel'"; cat "$work/out"
fi

printf '%s\n' "RAN: dns" > "$work/some.log"
if [ "$(check "$lists" "RAN: " "$work/some.log")" = 1 ] &&
  grep -qF "The test 'full tunnel'" "$work/out" && grep -qF "The test 'events'" "$work/out" &&
  ! grep -qF "The test 'dns'" "$work/out" && grep -q "2 of the 3 tests" "$work/out"; then
  pass "every test that did not run is named"
else
  fail "each missing name should be listed"; cat "$work/out"
fi

if [ "$(check "$lists" "RAN AS ROOT: " "$work/all.log")" = 1 ]; then
  pass "the prefix is part of the line"
else
  fail "'RAN: dns' must not satisfy 'RAN AS ROOT: dns'"; cat "$work/out"
fi

crlf=$work/crlf
mkdir -p "$crlf"
printf 'full tunnel\r\ndns\r\n' > "$crlf/a.txt"
printf 'RAN: full tunnel\r\nRAN: dns\r\n' > "$work/crlf.log"
if [ "$(check "$crlf" "RAN: " "$work/crlf.log")" = 0 ]; then
  pass "carriage returns are ignored in the lists and the log"
else
  fail "carriage returns should be ignored"; cat "$work/out"
fi

last=$work/last
mkdir -p "$last"
printf 'dns\nevents' > "$last/a.txt"
if [ "$(check "$last" "RAN: " "$work/some.log")" = 1 ] && grep -qF "The test 'events'" "$work/out"; then
  pass "a last line with no line end is still required"
else
  fail "a last line with no line end should be required"; cat "$work/out"
fi

if [ "$(check "$work/nothing-here" "RAN: " "$work/all.log")" = 1 ] && grep -q "no list of required tests" "$work/out"; then
  pass "a missing folder fails"
else
  fail "a missing folder should fail"; cat "$work/out"
fi

mkdir -p "$work/empty-folder"
if [ "$(check "$work/empty-folder" "RAN: " "$work/all.log")" = 1 ] && grep -q "no list of required tests" "$work/out"; then
  pass "a folder with no list fails"
else
  fail "a folder with no list should fail"; cat "$work/out"
fi

if [ "$(check "$lists" "RAN: " "$work/no.log")" = 1 ] && grep -q "There is no log" "$work/out"; then
  pass "a missing log fails"
else
  fail "a missing log should fail"; cat "$work/out"
fi

# Each must be refused for its own reason. <reason> <list content>
cases=0
refuse() {
  cases=$((cases + 1))
  local dir=$work/bad-$cases
  mkdir -p "$dir"
  printf '%s\n' "events" > "$dir/good.txt"
  printf '%s' "$2" > "$dir/bad.txt"
  if [ "$(check "$dir" "RAN: " "$work/all.log")" = 1 ] && grep -qF -- "$1" "$work/out"; then
    pass "refused: $3"
  else
    fail "a list was not refused with '$1' ($3):"; cat "$work/out"
  fi
}
refuse "names no test" "" "an empty list"
refuse "a line is blank" $'dns\n\nevents\n' "a blank line"
refuse "spaces at an end" $'dns \n' "a space at the end"
refuse "spaces at an end" $' dns\n' "a space at the start"
refuse "spaces at an end" $'dns\t\n' "a tab at the end"

# Every list in the repository is well formed: each passes against a log
# that holds exactly its own names.
for dir in "$here"/*/*/; do
  dir=${dir%/}
  cat "$dir"/*.txt | tr -d '\r' | sed 's/^/RAN: /' > "$work/own.log"
  if [ "$(check "$dir" "RAN: " "$work/own.log")" = 0 ]; then
    pass "${dir#"$here"/} is well formed"
  else
    fail "${dir#"$here"/} is not well formed:"; cat "$work/out"
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "$failures failed." >&2
  exit 1
fi
echo "All passed."
