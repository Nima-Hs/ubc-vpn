#!/usr/bin/env bash
# Installs what build.sh needs. Run in an MSYS2 UCRT64 shell. See README.md.
#
# Build tools come from the MSYS2 repository at whatever version it offers.
# The compiler and every library come from the exact files in packages.lock.
set -euo pipefail

PACKAGES=https://repo.msys2.org/mingw/ucrt64

[ "${MSYSTEM:-}" = UCRT64 ] || {
    echo "error: run this in an MSYS2 UCRT64 shell" >&2
    exit 1
}

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/cache"
cd "$here/cache"

pacman -S --needed --noconfirm - <"$here/build-tools.txt"

files=()
while read -r _ file; do
    if [ ! -f "$file" ]; then
        curl -fsSL -o "$file.part" "$PACKAGES/$file"
        mv "$file.part" "$file"
    fi
    files+=("$file")
done <"$here/packages.lock"
sha256sum --check --quiet "$here/packages.lock"

pacman -U --needed --noconfirm "${files[@]}"
