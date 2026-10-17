#!/usr/bin/env bash
# Runs cargo with these arguments, as the other scripts here do every time.
# On Windows, once token.ps1 has saved the workflow's token defaults, it goes
# through token.ps1, so the tests create what they create as they would
# outside Git Bash. MUTANTS_CARGO names another cargo, for test.sh.
set -euo pipefail

cargo=${MUTANTS_CARGO:-cargo}
if [ -z "${MUTANTS_TOKEN_OWNER:-}" ]; then
  exec "$cargo" "$@"
fi
here=$(cd "$(dirname "$0")" && pwd)
file=$(mktemp)
trap 'rm -f "$file"' EXIT
printf '%s\0' "$cargo" "$@" > "$file"
pwsh -NoLogo -NoProfile -NonInteractive -File "$(cygpath -w "$here/token.ps1")" run "$(cygpath -w "$file")"
