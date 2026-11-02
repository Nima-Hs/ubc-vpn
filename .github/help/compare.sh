#!/usr/bin/env bash
# Checks that the command-line client's help text (`ubc-vpn --help`) is the
# same on Windows, macOS and Linux, apart from lines marked as one system's
# own (.claude/rules/consistency.md).
#
# The marker: a line whose first word, after any indent, is "Windows:",
# "macOS:" or "Linux:" is meant for that system only. Such lines are left out
# of the comparison. Each system's help may hold only its own marked lines:
# one marked for another system fails the check, so a marker cannot hide a
# difference by mistake.
#
# Line endings are ignored. Needs only bash, grep, tr and diff; runs on
# macOS's bash 3.2 as well.
#
# Usage: .github/help/compare.sh <Windows help> <macOS help> <Linux help>
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <Windows help> <macOS help> <Linux help>" >&2
  exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
marker='^[[:space:]]*(Windows|macOS|Linux):'
systems="Windows macOS Linux"
status=0

i=0
for file in "$@"; do
  i=$((i + 1))
  system=$(echo "$systems" | cut -d' ' -f"$i")
  if [ ! -f "$file" ]; then
    echo "There is no $system help text: $file"
    status=1
    continue
  fi
  tr -d '\r' < "$file" > "$work/$system.full"
  # Without this, three copies of the same error message would pass.
  if [ "$(head -n 1 "$work/$system.full")" != "Usage: ubc-vpn <command>" ]; then
    echo "The $system help text does not start as help text does: $file"
    status=1
    continue
  fi
  if grep -nE "$marker" "$work/$system.full" | grep -vE "^[0-9]+:[[:space:]]*$system:"; then
    echo "The $system help text has the lines above, marked for another system."
    status=1
  fi
  grep -vE "$marker" "$work/$system.full" > "$work/$system" || true
done
if [ "$status" -ne 0 ]; then
  exit 1
fi

for system in macOS Linux; do
  if ! (cd "$work" && diff -u Windows "$system"); then
    echo "The help text on $system differs from Windows (above). Make it the same, or"
    echo "start a line meant for one system with its name, such as \"$system:\"."
    status=1
  fi
done
if [ "$status" -ne 0 ]; then
  exit 1
fi
echo "The help text is the same on Windows, macOS and Linux."
