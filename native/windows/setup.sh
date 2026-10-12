#!/usr/bin/env bash
# Installs what build.sh needs, from the exact package files in tools.lock
# (build tools) and packages.lock (compiler and libraries). It also downloads
# the files in control.lock, which the tests unpack but nothing installs.
# Run in an MSYS2 UCRT64 shell. See README.md.
set -euo pipefail
. "$(dirname "$0")/common.sh"
require_ucrt64

mkdir -p "$here/cache/packages"
cd "$here/cache/packages"

# fetch <lock file> <repository>
fetch() {
    local file
    while read -r _ file; do
        if [ ! -f "$file" ]; then
            curl -fsSL -o "$file.part" "$2/$file"
            mv "$file.part" "$file"
        fi
    done <"$here/$1"
    sha256sum --check --quiet "$here/$1"
}

fetch tools.lock "$MSYS_PACKAGES"
fetch packages.lock "$MINGW_PACKAGES"
fetch control.lock "$MINGW_PACKAGES"

# shellcheck disable=SC2046 # one argument per file name
pacman -U --needed --noconfirm $(cut -d' ' -f3 "$here/tools.lock" "$here/packages.lock")
