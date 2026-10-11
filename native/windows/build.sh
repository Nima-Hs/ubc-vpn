#!/usr/bin/env bash
# Builds libopenconnect for Windows x64 and gathers everything that must ship
# with it into out/. Run in an MSYS2 UCRT64 shell, after setup.sh. See README.md.
set -euo pipefail

VERSION=9.21
COMMIT=8b702bf2dbaf11302ed98629214b1df5d50a12aa
REPO=https://gitlab.com/openconnect/openconnect.git

PREFIX=/ucrt64
PACKAGES=https://repo.msys2.org/mingw/ucrt64
SOURCES=https://repo.msys2.org/mingw/sources
# Linked statically into the DLL we build: C runtime start-up code and libgcc.
STATIC_RUNTIME="mingw-w64-ucrt-x86_64-crt mingw-w64-ucrt-x86_64-headers mingw-w64-ucrt-x86_64-gcc"

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
mkdir -p "$work/sources" "$out/bin" "$out/licenses/openconnect" "$out/source"

# --- The compiler and libraries must be the ones in packages.lock ------------

# Sets version, pkgfile and pkgsha for an installed package.
locked() {
    version=$(pacman -Q "$1" | cut -d' ' -f2) || die "$1 is not installed; run setup.sh"
    pkgfile=$1-$version-any.pkg.tar.zst
    pkgsha=$(awk -v f="$pkgfile" '$2 == f { print $1 }' "$here/packages.lock")
    [ -n "$pkgsha" ] || die "$1 $version is installed but is not the version in packages.lock; run setup.sh"
}

while read -r _ file; do
    name=${file%-any.pkg.tar.zst} # name-pkgver-pkgrel
    name=${name%-*-*}
    locked "$name"
done <"$here/packages.lock"

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
./configure --with-gnutls --without-lz4 --disable-nls --disable-docs \
    --without-libproxy --without-stoken --without-libpskc --without-libpcsclite \
    --with-vpnc-script=vpnc-script-win.js
make -j"$(nproc)" libopenconnect.la
cp .libs/libopenconnect-5.dll "$out/bin/"
cp COPYING.LGPL "$out/licenses/openconnect/"
cd "$here"

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

declare -A files_of
for name in "${todo[@]:1}"; do
    pkg=$(pacman -Qqo "$PREFIX/bin/$name")
    files_of[$pkg]+="$name "
done

# --- Per MSYS2 package: licence, licence text and source ---------------------

# Sets srcfile and srcsha. Downloads the MSYS2 source package the installed
# binary was built from into out/source, and checks its signature.
fetch_source() {
    local pkgbase=$1
    srcfile=$pkgbase-$version.src.tar.zst
    curl -fsSL -o "$work/sources/$srcfile" "$SOURCES/$srcfile" &&
        curl -fsSL -o "$work/sources/$srcfile.sig" "$SOURCES/$srcfile.sig" ||
        die "cannot download the source of $pkg from $SOURCES/$srcfile"
    pacman-key --verify "$work/sources/$srcfile.sig" ||
        die "the signature of $srcfile is not from an MSYS2 packager"
    mv "$work/sources/$srcfile" "$out/source/"
    srcsha=$(sha256 "$out/source/$srcfile")
}

# Copies a package's licence text to out/licenses: the files the package
# installed or, if it installed none, those at the top of its upstream source.
copy_licence_text() {
    local dest=$out/licenses/$pkg f inner
    mkdir -p "$dest"
    while read -r f; do
        mkdir -p "$(dirname "$dest/${f#"$PREFIX"/share/licenses/*/}")"
        cp "$f" "$dest/${f#"$PREFIX"/share/licenses/*/}"
    done < <(pacman -Qlq "$pkg" | grep "^$PREFIX/share/licenses/.*[^/]\$" || true)
    [ -z "$(ls -A "$dest")" ] || return 0

    [ -n "${srcfile:-}" ] || die "$pkg installs no licence text"
    mkdir -p "$work/unpacked/$pkg"
    tar -xf "$out/source/$srcfile" -C "$work/unpacked/$pkg"
    for inner in "$work/unpacked/$pkg"/*/*.tar.*; do
        case $inner in *.sig | *.asc) continue ;; esac
        tar -xf "$inner" -C "$dest" --strip-components=1 --wildcards --no-wildcards-match-slash \
            '*/COPYING*' '*/LICEN[CS]E*' 2>/dev/null || true # either pattern may match nothing
    done
    [ -n "$(ls -A "$dest")" ] || die "no licence text found for $pkg in $srcfile"
}

json_files() {
    local sep="" name
    for name in "$@"; do
        printf '%s\n        {"name": "bin/%s", "sha256": "%s"}' "$sep" "$name" "$(sha256 "$out/bin/$name")"
        sep=,
    done
}

components=""
for pkg in $(printf '%s\n' "${!files_of[@]}" | sort) $STATIC_RUNTIME; do
    locked "$pkg"
    licence=$(awk -v p="$pkg" '$1 == p { sub(/^[^ ]+ +/, ""); print }' "$here/licences.txt")
    [ -n "$licence" ] || die "$pkg is not in licences.txt; review its licence before it ships"
    declared=$(LC_ALL=C pacman -Qi "$pkg" | sed -n 's/^Licenses *: //p' | sed 's/spdx://g; s/   */, /g')

    srcfile=""
    detail='"linked": "statically, into libopenconnect-5.dll"'
    if [ -n "${files_of[$pkg]:-}" ]; then
        pkgbase=$(sed -n '/^%BASE%$/{n;p}' "/var/lib/pacman/local/$pkg-$version/desc")
        [ -n "$pkgbase" ] || die "cannot tell which source package $pkg was built from"
        fetch_source "$pkgbase"
        # shellcheck disable=SC2086 # the file list is split on purpose
        detail=$(printf '"source": {"pkgbase": "%s", "file": "source/%s", "url": "%s", "sha256": "%s"},\n      "files": [%s\n      ]' \
            "$pkgbase" "$srcfile" "$SOURCES/$srcfile" "$srcsha" "$(json_files ${files_of[$pkg]})")
    fi
    copy_licence_text

    components+=$(
        cat <<EOF
,
    {
      "name": "$pkg",
      "version": "$version",
      "licence": "$licence",
      "licence_declared": "$declared",
      "licence_text": "licenses/$pkg/",
      "package": {"file": "$pkgfile", "url": "$PACKAGES/$pkgfile", "sha256": "$pkgsha"},
      $detail
    }
EOF
    )
done

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

# Every package of the build environment, build tools included.
pacman -Q >"$out/build-packages.txt"

echo "Built $out:"
ls -l "$out/bin" "$out/source"
