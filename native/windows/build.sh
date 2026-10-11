#!/usr/bin/env bash
# Builds libopenconnect for Windows x64 and gathers everything that must ship
# with it into out/. Run in an MSYS2 UCRT64 shell, after setup.sh. See README.md.
set -euo pipefail
. "$(dirname "$0")/common.sh"
require_ucrt64

VERSION=9.21
COMMIT=8b702bf2dbaf11302ed98629214b1df5d50a12aa
REPO=https://gitlab.com/openconnect/openconnect.git
# Linked statically into the DLLs we build: C runtime start-up code and libgcc.
STATIC_RUNTIME="mingw-w64-ucrt-x86_64-crt mingw-w64-ucrt-x86_64-headers mingw-w64-ucrt-x86_64-gcc"

rm -rf "$work" "$out"
mkdir -p "$work/sources" "$out/bin" "$out/licenses/openconnect" "$out/licenses/gnutls" "$out/source"

# --- The installed packages must be the locked ones --------------------------

# Every installed MinGW package must be a locked one, and the other way round:
# an extra package could supply a header or a static library unnoticed.
diff <(pacman -Q | sed -n 's/^\(mingw-w64-ucrt-x86_64-[^ ]*\) \(.*\)$/\1-\2-any.pkg.tar.zst/p' | sort) \
    <(cut -d' ' -f3 "$here/packages.lock" | sort) ||
    die "the installed MinGW packages (<) are not those in packages.lock (>); run setup.sh"

# Every build tool in tools.lock must be installed at that version. The rest of
# MSYS2 (the shell, coreutils, pacman) is whatever the machine has.
missing=$(comm -23 \
    <(cut -d' ' -f3 "$here/tools.lock" | sed -E 's/-(x86_64|any)\.pkg\.tar\.zst$//' | sort) \
    <(pacman -Q | sed 's/ /-/' | sort))
[ -z "$missing" ] || die "not installed at the version in tools.lock; run setup.sh:"$'\n'"$missing"

# Sets version, pkgfile and pkgsha for an installed MinGW package.
locked() {
    version=$(pacman -Q "$1" | cut -d' ' -f2) || die "$1 is not installed; run setup.sh"
    pkgfile=$1-$version-any.pkg.tar.zst
    pkgsha=$(locked_sha packages.lock "$pkgfile")
}

# --- GnuTLS, built from source or reused from an earlier build ---------------

"$here/gnutls.sh"
gnutls_sha=$(locked_sha sources.lock "$GNUTLS_TARBALL")
[ "$(sha256 "$gnutls/$GNUTLS_TARBALL")" = "$gnutls_sha" ] ||
    die "$GNUTLS_TARBALL does not have the SHA-256 in sources.lock"
cp "$gnutls/$GNUTLS_TARBALL" "$out/source/"
tar -xf "$gnutls/$GNUTLS_TARBALL" -C "$out/licenses/gnutls" --strip-components=1 \
    "gnutls-$GNUTLS_VERSION/COPYING" "gnutls-$GNUTLS_VERSION/COPYING.LESSERv2"

# --- OpenConnect: the tag must still point at the pinned commit --------------

git init --quiet --bare "$work/git"
git -C "$work/git" fetch --quiet --depth 1 "$REPO" "refs/tags/v$VERSION"
fetched=$(git -C "$work/git" rev-parse "FETCH_HEAD^{commit}")
[ "$fetched" = "$COMMIT" ] || die "tag v$VERSION is $fetched, expected $COMMIT"

archive=openconnect-$VERSION.tar.gz
git -C "$work/git" -c core.autocrlf=false archive \
    --prefix="openconnect-$VERSION/" -o "$out/source/$archive" "$COMMIT"
cp "$here"/patches/*.patch "$out/source/"

# --- Build it, from the archive and patches that ship ------------------------

tar -xzf "$out/source/$archive" -C "$work"
cd "$work/openconnect-$VERSION"
for p in "$out"/source/*.patch; do
    patch -p1 <"$p"
done
./autogen.sh
# -ffile-prefix-map keeps this folder's path out of the DLL.
PKG_CONFIG_PATH=$gnutls/lib/pkgconfig ./configure \
    --with-gnutls --without-lz4 --disable-nls --disable-docs \
    --without-libproxy --without-stoken --without-libpskc --without-libpcsclite \
    --with-vpnc-script=vpnc-script-win.js \
    CFLAGS="-O2 -ffile-prefix-map=$(cygpath -m "$work")=."
make -j"$(nproc)" libopenconnect.la
cp .libs/libopenconnect-5.dll "$out/bin/"
cp COPYING.LGPL "$out/licenses/openconnect/"

# See the same check in gnutls.sh.
included=$(find . -name '*.Plo' -exec cat {} +)
grep -q '/include/windows\.h' <<<"$included" || die "the compiler's dependency files are missing"
! grep -q '/ddk/' <<<"$included" || die "a DDK header is compiled in; review the headers entry in licences.txt"
cd "$here"

# --- Dependencies: follow the import tables, starting from our DLL -----------

collect_dlls "$out/bin" libopenconnect-5.dll "$gnutls/bin" "$PREFIX/bin" >"$work/dlls.list"
declare -A files_of
gnutls_files=""
while read -r name dir; do
    if [ "$dir" = "$gnutls/bin" ]; then
        gnutls_files+="$name "
    else
        files_of[$(pacman -Qqo "$dir/$name")]+="$name "
    fi
done <"$work/dlls.list"

# dlls.txt is the list of DLLs we expect, each with the reason it is needed.
diff <(ls "$out/bin") <(grep -v '^#' "$here/dlls.txt" | awk 'NF { print $1 }' | sort) ||
    die "the DLLs in the output (<) are not those in dlls.txt (>)"

# --- Per MSYS2 package: licence, licence text and source ---------------------

# Sets pkgbase, srcfile and srcsha: the MSYS2 source package the installed
# binary was built from, which must be listed in sources.lock.
locked_source() {
    pkgbase=$(sed -n '/^%BASE%$/{n;p}' "/var/lib/pacman/local/$pkg-$version/desc")
    [ -n "$pkgbase" ] || die "cannot tell which source package $pkg was built from"
    srcfile=$pkgbase-$version.src.tar.zst
    srcsha=$(locked_sha sources.lock "$srcfile")
}

# Downloads that source package into out/source, and checks it against
# sources.lock and against the signature of an MSYS2 packager.
fetch_source() {
    curl -fsSL -o "$work/sources/$srcfile" "$SOURCES/$srcfile" &&
        curl -fsSL -o "$work/sources/$srcfile.sig" "$SOURCES/$srcfile.sig" ||
        die "cannot download the source of $pkg from $SOURCES/$srcfile"
    [ "$(sha256 "$work/sources/$srcfile")" = "$srcsha" ] ||
        die "$srcfile does not have the SHA-256 in sources.lock"
    gpg --homedir "$work/gnupg" --no-permission-warning --batch --quiet --verify \
        "$work/sources/$srcfile.sig" "$work/sources/$srcfile" ||
        die "the signature of $srcfile is not from an MSYS2 packager"
    mv "$work/sources/$srcfile" "$out/source/"
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

    [ -f "$out/source/$srcfile" ] || die "$pkg installs no licence text"
    mkdir -p "$work/unpacked/$pkg"
    tar -xf "$out/source/$srcfile" -C "$work/unpacked/$pkg"
    for inner in "$work/unpacked/$pkg"/*/*.tar.*; do
        case $inner in *.sig | *.asc) continue ;; esac
        tar -xf "$inner" -C "$dest" --strip-components=1 --wildcards --no-wildcards-match-slash \
            '*/COPYING*' '*/LICEN[CS]E*' 2>/dev/null || true # either pattern may match nothing
    done
    [ -n "$(ls -A "$dest")" ] || die "no licence text found for $pkg in $srcfile"
}

# Prints the licence we use a component under, which licences.txt must name.
elected_licence() {
    local licence
    licence=$(awk -v p="$1" '$1 == p { sub(/^[^ ]+ +/, ""); print }' "$here/licences.txt")
    [ -n "$licence" ] || die "$1 is not in licences.txt; review its licence before it ships"
    echo "$licence"
}

json_files() {
    local sep="" name
    for name in "$@"; do
        printf '%s\n        {"name": "bin/%s", "sha256": "%s"}' "$sep" "$name" "$(sha256 "$out/bin/$name")"
        sep=,
    done
}

# MSYS2's packager keys, in a keyring of our own: pacman's is not always readable.
mkdir "$work/gnupg"
gpg --homedir "$work/gnupg" --no-permission-warning --batch --quiet \
    --import /usr/share/pacman/keyrings/msys2.gpg

components=""
for pkg in $(printf '%s\n' "${!files_of[@]}" | sort) $STATIC_RUNTIME; do
    locked "$pkg"
    licence=$(elected_licence "$pkg")
    declared=$(LC_ALL=C pacman -Qi "$pkg" | sed -n 's/^Licenses *: //p' | sed 's/spdx://g; s/   */, /g')

    locked_source
    if [ -n "${files_of[$pkg]:-}" ]; then
        fetch_source
        # shellcheck disable=SC2086 # the file list is split on purpose
        detail=$(printf '"source": {"pkgbase": "%s", "file": "source/%s", "url": "%s", "sha256": "%s"},\n      "files": [%s\n      ]' \
            "$pkgbase" "$srcfile" "$SOURCES/$srcfile" "$srcsha" "$(json_files ${files_of[$pkg]})")
    else
        # The static runtime's source is recorded but not shipped.
        detail=$(printf '"source": {"pkgbase": "%s", "shipped": false, "url": "%s", "sha256": "%s"},\n      "linked": "statically, into the DLLs built from source"' \
            "$pkgbase" "$SOURCES/$srcfile" "$srcsha")
    fi
    copy_licence_text

    components+=$(
        cat <<EOF
,
    {
      "name": "$pkg",
      "origin": "MSYS2 package",
      "version": "$version",
      "licence": "$licence",
      "licence_declared": "$declared",
      "licence_text": "licenses/$pkg/",
      "package": {"file": "$pkgfile", "url": "$MINGW_PACKAGES/$pkgfile", "sha256": "$pkgsha"},
      $detail
    }
EOF
    )
done

patches=$(cd "$out" && printf '"%s", ' source/*.patch)
# shellcheck disable=SC2086 # the file list is split on purpose
cat >"$out/manifest.json" <<EOF
{
  "target": "x86_64-w64-mingw32 (MSYS2 UCRT64)",
  "shippable": false,
  "blockers": ["The tests in the Native library (Windows) workflow have not passed on this output."],
  "components": [
    {
      "name": "openconnect",
      "origin": "built from source",
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
    },
    {
      "name": "gnutls",
      "origin": "built from source",
      "version": "$GNUTLS_VERSION",
      "licence": "$(elected_licence gnutls)",
      "licence_text": "licenses/gnutls/",
      "source": {"file": "source/$GNUTLS_TARBALL", "url": "$GNUTLS_URL", "sha256": "$gnutls_sha"},
      "files": [$(json_files $gnutls_files)
      ]
    }$components
  ]
}
EOF

# Every MSYS2 package of the build environment, build tools included.
pacman -Q >"$out/build-packages.txt"

echo "Built $out:"
ls -l "$out/bin" "$out/source"
