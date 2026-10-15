#!/usr/bin/env bash
# Tests for packaging/windows/check-native.mjs, run by
# .github/workflows/installer-windows.yml before staging and safe to run
# anywhere: it only builds small made-up artifacts in a temporary folder.
#
#   packaging/windows/tests/check-native.sh
#
# An artifact matching its manifest passes; one with a changed, extra or
# missing library or source archive is refused.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
check="$root/packaging/windows/check-native.mjs"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

# make <folder>: an artifact with two libraries, two source archives, the
# recipe, and a source recorded but not shipped, all listed in its manifest.
make() {
  local a=$1
  mkdir -p "$a/bin" "$a/source/recipe/patches"
  printf 'library one\n' >"$a/bin/libone-1.dll"
  printf 'library two\n' >"$a/bin/libtwo-2.dll"
  printf 'source one\n' >"$a/source/one-1.0.tar.gz"
  printf 'source two\n' >"$a/source/two-2.0.tar.zst"
  printf 'a patch\n' >"$a/source/recipe/patches/fix.patch"
  cat >"$a/manifest.json" <<EOF
{
  "shippable": true,
  "components": [
    {
      "name": "one",
      "source": {"archive": "source/one-1.0.tar.gz", "sha256": "$(sha "$a/source/one-1.0.tar.gz")"},
      "files": [{"name": "bin/libone-1.dll", "sha256": "$(sha "$a/bin/libone-1.dll")"}]
    },
    {
      "name": "two",
      "source": {"file": "source/two-2.0.tar.zst", "sha256": "$(sha "$a/source/two-2.0.tar.zst")"},
      "files": [{"name": "bin/libtwo-2.dll", "sha256": "$(sha "$a/bin/libtwo-2.dll")"}]
    },
    {
      "name": "runtime",
      "source": {"shipped": false, "sha256": "$(printf '0%.0s' {1..64})"},
      "linked": "statically"
    }
  ]
}
EOF
}

failed=0
# expect <pass|refuse> <what> <folder>
expect() {
  local want=$1 what=$2 folder=$3 got
  if node "$check" "$folder" >"$work/out" 2>&1; then got=pass; else got=refuse; fi
  if [ "$got" = "$want" ]; then
    echo "ok: $what ($want)"
  else
    echo "FAILED: $what: wanted $want, got $got" >&2
    cat "$work/out" >&2
    failed=1
  fi
}

# case_ <name>: a fresh copy of the good artifact, in $work/<name>.
case_() {
  make "$work/$1"
  echo "$work/$1"
}

a=$(case_ good)
expect pass 'an artifact matching its manifest' "$a"

a=$(case_ changed-dll)
printf 'changed\n' >>"$a/bin/libone-1.dll"
expect refuse 'a library changed after the manifest was written' "$a"

a=$(case_ extra-dll)
printf 'extra\n' >"$a/bin/libextra-1.dll"
expect refuse 'a library the manifest does not list' "$a"

a=$(case_ missing-dll)
rm "$a/bin/libtwo-2.dll"
expect refuse 'a listed library that is missing' "$a"

a=$(case_ changed-source)
printf 'changed\n' >>"$a/source/two-2.0.tar.zst"
expect refuse 'a source archive changed after the manifest was written' "$a"

a=$(case_ extra-source)
printf 'extra\n' >"$a/source/three-3.0.tar.gz"
expect refuse 'a source archive the manifest does not list' "$a"

a=$(case_ missing-source)
rm "$a/source/one-1.0.tar.gz"
expect refuse 'a listed source archive that is missing' "$a"

a=$(case_ no-checksum)
sed -i 's/"sha256": "[0-9a-f]*"}]/"sha256": ""}]/' "$a/manifest.json"
expect refuse 'a listed library without a checksum' "$a"

# stage.sh runs the check first: it stops on a changed library, saying so,
# before it builds or stages anything.
a=$(case_ staged)
printf 'changed\n' >>"$a/bin/libone-1.dll"
if "$root/packaging/windows/stage.sh" "$a" 1 "$work/sources.tar.gz" >"$work/out" 2>&1; then
  echo 'FAILED: stage.sh staged a changed library' >&2
  failed=1
elif ! grep -q '^bin/libone-1.dll: SHA-256 ' "$work/out"; then
  echo 'FAILED: stage.sh stopped, but not at the checksum check:' >&2
  cat "$work/out" >&2
  failed=1
else
  echo 'ok: stage.sh stops at a changed library'
fi

exit $failed
