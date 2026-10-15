#!/usr/bin/env bash
# Installs the pinned MSYS2 base into a new folder, so that the build runs on
# a known MSYS2 rather than whatever the machine has. Run from Git Bash, not
# from MSYS2 itself.
# Usage: base.sh <folder to create, such as /c/msys2-pinned>
#
# The archive is named in base.lock with its SHA-256. base-packages.txt lists
# the packages it holds; build.sh stops if the installed MSYS packages are not
# exactly those plus the ones in tools.lock.
set -euo pipefail

DISTRIB=https://repo.msys2.org/distrib/x86_64

die() {
    echo "error: $*" >&2
    exit 1
}

[ $# -eq 1 ] || die "usage: base.sh <folder to create>"
target=$1
[ ! -e "$target" ] || die "$target already exists"

here=$(cd "$(dirname "$0")" && pwd)
read -r sha archive <"$here/base.lock"
mkdir -p "$here/cache"
download=$here/cache/$archive
if [ ! -f "$download" ]; then
    curl -fsSL -o "$download.part" "$DISTRIB/$archive"
    mv "$download.part" "$download"
fi
echo "$sha *$download" | sha256sum -c -

# The archive holds a single folder, msys64.
parent=$(dirname "$target")
mkdir -p "$parent/.base-unpack"
tar -xJf "$download" -C "$parent/.base-unpack"
mv "$parent/.base-unpack/msys64" "$target"
rmdir "$parent/.base-unpack"

# The first login sets MSYS2 up: it creates the home folder and pacman's
# keyring. Nothing is downloaded and no package is changed.
MSYSTEM=UCRT64 CHERE_INVOKING=yes "$target/usr/bin/bash.exe" -lc 'echo "MSYS2 base ready: $(uname -r)"'
