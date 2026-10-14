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
read -r sha archive extra <"$here/base.lock"
[[ $sha =~ ^[0-9a-f]{64}$ ]] && [[ $archive =~ ^msys2-base-x86_64-[0-9]{8}\.tar\.xz$ ]] && [ -z "${extra:-}" ] ||
    die "base.lock must be one line: a SHA-256 and a dated msys2-base archive name"
mkdir -p "$here/cache"
download=$here/cache/$archive
if [ ! -f "$download" ]; then
    curl -fsSL -o "$download.part" "$DISTRIB/$archive"
    mv "$download.part" "$download"
fi
# Nothing is unpacked unless the archive is the pinned one. A mismatched file
# is deleted, so that the next run fetches it again rather than reusing it.
actual=$(sha256sum "$download" | cut -d' ' -f1)
if [ "$actual" != "$sha" ]; then
    rm -f "$download"
    die "$archive has SHA-256 $actual, not $sha as base.lock says"
fi
echo "$archive: SHA-256 matches base.lock"

# The archive holds a single folder, msys64.
parent=$(dirname "$target")
mkdir -p "$parent/.base-unpack"
tar -xJf "$download" -C "$parent/.base-unpack"
mv "$parent/.base-unpack/msys64" "$target"
rmdir "$parent/.base-unpack"

# The first login sets MSYS2 up: it creates the home folder and pacman's
# keyring. Nothing is downloaded and no package is changed.
MSYSTEM=UCRT64 CHERE_INVOKING=yes "$target/usr/bin/bash.exe" -lc 'echo "MSYS2 base ready: $(uname -r)"'
