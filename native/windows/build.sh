#!/usr/bin/env bash
# Builds libopenconnect for Windows x64 and gathers everything that must ship
# with it into out/. Run in an MSYS2 UCRT64 shell. See README.md.
set -euo pipefail

VERSION=9.21
COMMIT=8b702bf2dbaf11302ed98629214b1df5d50a12aa
REPO=https://gitlab.com/openconnect/openconnect.git
PREFIX=/ucrt64

die() {
    echo "error: $*" >&2
    exit 1
}

sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

[ "${MSYSTEM:-}" = UCRT64 ] || die "run this in an MSYS2 UCRT64 shell"

here=$(cd "$(dirname "$0")" && pwd)
work=$here/work
out=$here/out
rm -rf "$work" "$out"
mkdir -p "$work" "$out/bin" "$out/licenses/openconnect" "$out/source"

# --- Source: the tag must still point at the pinned commit -------------------

git init --quiet --bare "$work/git"
git -C "$work/git" fetch --quiet --depth 1 "$REPO" "refs/tags/v$VERSION"
fetched=$(git -C "$work/git" rev-parse "FETCH_HEAD^{commit}")
[ "$fetched" = "$COMMIT" ] || die "tag v$VERSION is $fetched, expected $COMMIT"

archive=openconnect-$VERSION.tar.gz
git -C "$work/git" -c core.autocrlf=false archive \
    --prefix="openconnect-$VERSION/" -o "$out/source/$archive" "$COMMIT"
cp "$here"/patches/*.patch "$out/source/"

# --- Build, from the archive and patches that ship ---------------------------

tar -xzf "$out/source/$archive" -C "$work"
cd "$work/openconnect-$VERSION"
for p in "$out"/source/*.patch; do
    patch -p1 <"$p"
done
./autogen.sh
./configure --with-gnutls --disable-nls --disable-docs \
    --without-libproxy --without-stoken --without-libpskc --without-libpcsclite \
    --with-vpnc-script=vpnc-script-win.js
make -j"$(nproc)" libopenconnect.la
cp .libs/libopenconnect-5.dll "$out/bin/"
cp COPYING.LGPL "$out/licenses/openconnect/"

# --- Dependencies: follow the import tables, starting from our DLL -----------

system32=$(cygpath -u "$SYSTEMROOT")/System32
todo=(libopenconnect-5.dll)
for ((i = 0; i < ${#todo[@]}; i++)); do
    for name in $(objdump -p "$out/bin/${todo[i]}" | sed -n 's/^\s*DLL Name: //p'); do
        if [ -e "$out/bin/$name" ]; then
            continue
        elif [ -e "$PREFIX/bin/$name" ]; then
            cp "$PREFIX/bin/$name" "$out/bin/"
            todo+=("$name")
        elif [ -e "$system32/$name" ] || [[ ${name,,} == api-ms-win-* ]]; then
            continue # Part of Windows.
        else
            die "$name, needed by ${todo[i]}, is in neither $PREFIX/bin nor $system32"
        fi
    done
done

# --- Which MSYS2 package each bundled DLL came from, and its licence ---------

declare -A files_of
for name in "${todo[@]:1}"; do
    pkg=$(pacman -Qqo "$PREFIX/bin/$name")
    files_of[$pkg]+="$name "
done

json_files() {
    local sep="" name
    for name in "$@"; do
        printf '%s\n        {"name": "bin/%s", "sha256": "%s"}' "$sep" "$name" "$(sha256 "$out/bin/$name")"
        sep=,
    done
}

missing=()
components=""
for pkg in $(printf '%s\n' "${!files_of[@]}" | sort); do
    version=$(pacman -Q "$pkg" | cut -d' ' -f2)
    licence=$(LC_ALL=C pacman -Qi "$pkg" | sed -n 's/^Licenses *: //p' | sed 's/spdx://g; s/   */, /g')

    copied=0
    while read -r f; do
        dest=$out/licenses/$pkg/${f#"$PREFIX"/share/licenses/*/}
        mkdir -p "$(dirname "$dest")"
        cp "$f" "$dest"
        copied=1
    done < <(pacman -Qlq "$pkg" | grep "^$PREFIX/share/licenses/.*[^/]\$" || true)
    [ "$copied" = 1 ] || missing+=("$pkg")

    # shellcheck disable=SC2086 # the file list is split on purpose
    components+=$(printf ',\n    {\n      "name": "%s",\n      "version": "%s",\n      "licence": "%s",\n      "licence_text": "licenses/%s/",\n      "files": [%s\n      ]\n    }' \
        "$pkg" "$version" "$licence" "$pkg" "$(json_files ${files_of[$pkg]})")
done
[ ${#missing[@]} -eq 0 ] || die "no licence text installed for: ${missing[*]}"

patches=$(cd "$out" && printf '"%s", ' source/*.patch)
cat >"$out/manifest.json" <<EOF
{
  "target": "x86_64-w64-mingw32 (MSYS2 UCRT64)",
  "components": [
    {
      "name": "openconnect",
      "version": "$VERSION",
      "licence": "LGPL-2.1-only",
      "licence_text": "licenses/openconnect/",
      "source": {
        "repository": "$REPO",
        "commit": "$COMMIT",
        "archive": "source/$archive",
        "sha256": "$(sha256 "$out/source/$archive")",
        "patches": [${patches%, }]
      },
      "files": [$(json_files libopenconnect-5.dll)
      ]
    }$components
  ]
}
EOF

# Every package of the build environment, compiler and C runtime included.
pacman -Q >"$out/build-packages.txt"

echo "Built $out:"
ls -l "$out/bin"
