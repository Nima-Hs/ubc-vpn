#!/usr/bin/env bash
# Tests for compare.sh. Needs only bash and coreutils; runs on macOS's
# bash 3.2 as well.
#
# Usage: .github/help/test.sh
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

compare() { # <Windows> <macOS> <Linux>: the status, with the output in $work/out
  local status=0
  bash "$here/compare.sh" "$@" > "$work/out" 2>&1 || status=$?
  echo "$status"
}

help() { # <file> <lines...>: a help text with these lines after the usual ones
  local file=$1
  shift
  printf '%s\n' "Usage: ubc-vpn <command>" "" "Commands:" "  status   Show the state" > "$file"
  if [ $# -gt 0 ]; then
    printf '%s\n' "$@" >> "$file"
  fi
}

help "$work/w" "Exit status:"
help "$work/m" "Exit status:"
help "$work/l" "Exit status:"
if [ "$(compare "$work/w" "$work/m" "$work/l")" = 0 ] && grep -q "is the same on Windows, macOS and Linux" "$work/out"; then
  pass "the same text passes"
else
  fail "the same text should pass"; cat "$work/out"
fi

help "$work/m2" "Exit status: "
if [ "$(compare "$work/w" "$work/m2" "$work/l")" = 1 ] &&
  grep -q "on macOS differs from Windows" "$work/out" && ! grep -q "on Linux differs" "$work/out"; then
  pass "a difference of one space fails, naming the system"
else
  fail "a different line on macOS should fail"; cat "$work/out"
fi

help "$work/l2" "Exit status:" "  logs     Show the log"
if [ "$(compare "$work/w" "$work/m" "$work/l2")" = 1 ] && grep -q "^+  logs" "$work/out"; then
  pass "an extra line fails, and is shown"
else
  fail "an extra line on Linux should fail"; cat "$work/out"
fi

help "$work/wm" "Exit status:" "  Windows: sc start ubc-vpn"
help "$work/mm" "Exit status:" "macOS: sudo launchctl kickstart"
help "$work/lm" "Linux: sudo systemctl start ubc-vpn" "Exit status:"
if [ "$(compare "$work/wm" "$work/mm" "$work/lm")" = 0 ]; then
  pass "lines marked as each system's own are left out"
else
  fail "each system's own marked lines should pass"; cat "$work/out"
fi

help "$work/mx" "Exit status:" "Linux: sudo systemctl start ubc-vpn"
if [ "$(compare "$work/w" "$work/mx" "$work/l")" = 1 ] &&
  grep -q "The macOS help text has the lines above, marked for another system" "$work/out"; then
  pass "a line marked for another system fails"
else
  fail "a Linux line in the macOS help should fail"; cat "$work/out"
fi

help "$work/mw" "Exit status:" "Note Windows: not a marker"
if [ "$(compare "$work/w" "$work/mw" "$work/l")" = 1 ]; then
  pass "a system's name later in a line is not a marker"
else
  fail "only the first word marks a line"; cat "$work/out"
fi

awk '{ printf "%s\r\n", $0 }' "$work/w" > "$work/wcrlf"
# One more byte for each line, or the copy has no carriage returns to ignore.
if [ $(($(wc -c < "$work/wcrlf") - $(wc -c < "$work/w"))) = "$(wc -l < "$work/w" | tr -d ' ')" ] && [ "$(compare "$work/wcrlf" "$work/m" "$work/l")" = 0 ]; then
  pass "line endings are ignored"
else
  fail "Windows line endings should not count"; cat "$work/out"
fi

echo "error: no such command" > "$work/e"
if [ "$(compare "$work/e" "$work/e" "$work/e")" = 1 ] && grep -q "does not start as help text does" "$work/out"; then
  pass "three copies of the same error fail"
else
  fail "a text that is not help should fail"; cat "$work/out"
fi

if [ "$(compare "$work/w" "$work/missing" "$work/l")" = 1 ] && grep -q "There is no macOS help text" "$work/out"; then
  pass "a missing text fails"
else
  fail "a missing file should fail"; cat "$work/out"
fi

if [ "$(compare "$work/w" "$work/m")" = 2 ]; then
  pass "it needs all three"
else
  fail "two files should be wrong usage"; cat "$work/out"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures failed" >&2
  exit 1
fi
echo "All passed."
