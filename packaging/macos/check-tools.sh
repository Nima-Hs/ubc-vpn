#!/usr/bin/env bash
# Shows which pkgbuild and productbuild electron-builder will find, and what
# they are. Both come with macOS, not from a package. The installer workflow
# runs it with the PATH `pnpm package:mac` gives electron-builder.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }

sw_vers
for tool in pkgbuild productbuild; do
    path=$(command -v "$tool") || fail "$tool is not on PATH"
    [ "$path" = "/usr/bin/$tool" ] || fail "$tool is found first at $path, not /usr/bin/$tool"
    shasum -a 256 "$path"
done
