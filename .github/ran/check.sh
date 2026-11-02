#!/usr/bin/env bash
# Proves from a test log that every test a workflow requires really ran. A
# test that is skipped passes, so each one that needs root, an elevated
# process, a gateway or a device prints a line when it ran, and the
# workflow requires the line.
#
# Usage: check.sh <folder> <prefix> <log>
#
# Every *.txt file in <folder> holds test names, one per line. Each name,
# after <prefix>, must be a whole line of <log>: "full tunnel" is not
# satisfied by "full tunnel foreign". Carriage returns are ignored in both,
# since PowerShell writes them. The folders are .github/ran/<workflow>/<os>,
# so a pull request that adds a test adds its name to a file there, or a
# file of its own, without changing the workflow.
#
# Fails, naming every test that did not run, if any did not; and fails if
# the folder has no list, a list names no test, or a line is blank or has
# spaces at either end. Runs on macOS's bash 3.2 as well.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: check.sh <folder> <prefix> <log>" >&2
  exit 2
fi
dir=$1 prefix=$2 log=$3

if ! [ -f "$log" ]; then
  echo "There is no log at $log." >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tr -d '\r' < "$log" > "$work/log"

lists=0 required=0 missing=0 bad=0
for list in "$dir"/*.txt; do
  # A pattern that matches nothing stays as it is.
  [ -f "$list" ] || continue
  lists=$((lists + 1))
  tr -d '\r' < "$list" > "$work/list"
  names=0 line=0
  while IFS= read -r name || [ -n "$name" ]; do
    line=$((line + 1))
    case $name in
      "" | " "* | *" " | "	"* | *"	")
        echo "$list:$line: a line is blank or has spaces at an end." >&2
        bad=1
        continue
        ;;
    esac
    names=$((names + 1))
    if ! grep -qxF -- "$prefix$name" "$work/log"; then
      echo "The test '$name' ($list) did not run: no line '$prefix$name' in the log." >&2
      missing=$((missing + 1))
    fi
  done < "$work/list"
  if [ "$names" -eq 0 ]; then
    echo "$list names no test." >&2
    bad=1
  fi
  required=$((required + names))
done

if [ "$lists" -eq 0 ]; then
  echo "There is no list of required tests (*.txt) in $dir." >&2
  exit 1
fi
if [ "$missing" -ne 0 ]; then
  echo "$missing of the $required tests $dir requires did not run." >&2
fi
if [ "$bad" -ne 0 ]; then
  echo "The lists in $dir are not as expected." >&2
fi
if [ "$bad" -ne 0 ] || [ "$missing" -ne 0 ]; then
  exit 1
fi
echo "All $required tests in $lists lists in $dir ran."
