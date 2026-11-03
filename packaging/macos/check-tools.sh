#!/usr/bin/env bash
# Checks and records the pkgbuild and productbuild that electron-builder will
# write the .pkg with. Both come with macOS, not from a package, so they cannot
# be pinned: .claude/rules/dependencies.md has the owner's exception, and this
# is its record. The installer workflow runs it with the PATH `pnpm package:mac`
# gives electron-builder.
#
# It stops unless this is the macOS the workflow's runner is pinned to, and each
# tool is found first in /usr/bin. It logs the macOS version and build, each
# tool's version as it records it, and each tool's SHA-256.
set -euo pipefail

# The major version of the workflow's `runs-on: macos-15`.
MACOS_MAJOR=15

fail() { echo "error: $*" >&2; exit 1; }

sw_vers
major=$(sw_vers -productVersion | cut -d. -f1)
[ "$major" = "$MACOS_MAJOR" ] || fail "this is macOS $major, not the $MACOS_MAJOR the package is built on"
for tool in pkgbuild productbuild; do
    path=$(command -v "$tool") || fail "$tool is not on PATH"
    [ "$path" = "/usr/bin/$tool" ] || fail "$tool is found first at $path, not /usr/bin/$tool"
    # The version the tool's own build records. None is a failure of the
    # record, which the exception relies on.
    version=$(what "$path" | sed -n 's/^[[:space:]]*//p' | grep -E '^PROGRAM:' | head -n 1 || true)
    [ -n "$version" ] || fail "$tool records no version"
    echo "$tool: $version"
    shasum -a 256 "$path"
done
