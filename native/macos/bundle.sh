#!/bin/bash
# Turns what build.sh produced into a folder that can be moved anywhere:
# libopenconnect and the libraries it needs, made relocatable and signed,
# with their licences, their sources and a manifest. Fails if any library
# does not meet the rules checked at the end.
#
# Usage: bundle.sh <work-dir> <out-dir>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=versions.env
. "$here/versions.env"

work=$(cd "${1:?usage: bundle.sh <work-dir> <out-dir>}" && pwd)
prefix=$work/prefix
sources=$work/sources
rm -rf "${2:?usage: bundle.sh <work-dir> <out-dir>}"
mkdir -p "$2/lib/pkgconfig" "$2/include" "$2/licenses" "$2/sources/recipe"
out=$(cd "$2" && pwd)

# The libraries a file loads. For a library the list includes its own name.
loads() {
    otool -L "$1" | awk 'NR > 1 { print $1 }'
}

# Copies a library and, in turn, everything it loads from our prefix.
collect() {
    local name=${1##*/} dep
    [ -f "$out/lib/$name" ] && return 0
    cp -L "$1" "$out/lib/$name"
    chmod 644 "$out/lib/$name"
    for dep in $(loads "$1"); do
        case $dep in
            "$prefix"/*) collect "$dep" ;;
            /usr/lib/* | /System/Library/*) ;;
            *)
                echo "$name loads $dep, which is neither ours nor the system's." >&2
                exit 1
                ;;
        esac
    done
}
collect "$prefix/lib/libopenconnect.5.dylib"

# Make each library findable next to the others instead of at its build path.
# Editing a library breaks its signature, and Apple silicon refuses to load
# unsigned code, so sign again (ad hoc) afterwards.
for lib in "$out"/lib/*.dylib; do
    install_name_tool -id "@rpath/${lib##*/}" "$lib"
    for dep in $(loads "$lib"); do
        case $dep in
            "$prefix"/*) install_name_tool -change "$dep" "@loader_path/${dep##*/}" "$lib" ;;
        esac
    done
    codesign --force --sign - "$lib"
done

minos() {
    otool -l "$1" | awk '/LC_BUILD_VERSION/ { found = 1 } found && $1 == "minos" { print $2; exit }'
}

# Check every library before anything else is written.
failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=1
}
for lib in "$out"/lib/*.dylib; do
    name=${lib##*/}
    [ "$(lipo -archs "$lib")" = arm64 ] || fail "$name is not arm64 only"
    [ "$(minos "$lib")" = "$MACOS_MIN" ] || fail "$name needs macOS $(minos "$lib"), not $MACOS_MIN"
    otool -hv "$lib" | grep -q TWOLEVEL || fail "$name uses a flat namespace"
    codesign --verify --strict "$lib" || fail "$name has no valid signature"
    if otool -l "$lib" | grep -q LC_RPATH; then
        fail "$name carries a search path of its own"
    fi
    for dep in $(loads "$lib"); do
        case $dep in
            @rpath/* | @loader_path/* | /usr/lib/* | /System/Library/*) ;;
            *) fail "$name loads $dep" ;;
        esac
    done
    if grep -q "$work" "$lib"; then
        fail "$name contains the build directory: $(strings -a "$lib" | grep "$work" | head -5)"
    fi
    echo "$name: macOS $(minos "$lib")"
    loads "$lib" | sed 's/^/    /'
done
[ "$failed" = 0 ]

ln -s libopenconnect.5.dylib "$out/lib/libopenconnect.dylib"
cp "$prefix/include/openconnect.h" "$out/include/"
cat > "$out/lib/pkgconfig/openconnect.pc" <<EOF
prefix=\${pcfiledir}/../..
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: openconnect
Description: OpenConnect VPN client library
Version: $OPENCONNECT_VERSION
Libs: -L\${libdir} -lopenconnect
Cflags: -I\${includedir}
EOF

# The LGPL asks us to ship the source we built from and how we built it.
cp "$sources"/* "$out/sources/"
cp "$here/build.sh" "$here/bundle.sh" "$here/versions.env" "$out/sources/recipe/"

licences() { # <component> <archive> <file>...
    local component=$1 archive=$2 file
    shift 2
    mkdir -p "$out/licenses/$component"
    for file in "$@"; do
        tar -xOf "$sources/$archive" "${archive%.tar.*}/$file" \
            > "$out/licenses/$component/${file//\//-}"
    done
}
openconnect_src=openconnect-$OPENCONNECT_VERSION.tar.gz
licences openconnect "$openconnect_src" COPYING.LGPL json/LICENSE
licences gnutls "${GNUTLS_URL##*/}" COPYING.LESSERv2
licences nettle "${NETTLE_URL##*/}" COPYING.LESSERv3 COPYINGv3 COPYINGv2
licences gmp "${GMP_URL##*/}" COPYING.LESSERv3 COPYINGv3 COPYINGv2

component() { # <name> <version> <licence> <archive> <library name prefix>...
    local name=$1 version=$2 licence=$3 archive=$4 libs="" lib
    shift 4
    for lib in "$@"; do
        lib=$(cd "$out" && echo lib/"$lib".*.dylib)
        libs="$libs${libs:+, }\"$lib\""
    done
    cat <<EOF
    {
      "name": "$name",
      "version": "$version",
      "licence": "$licence",
      "min_macos": "$(minos "$out/${lib}")",
      "libraries": [$libs],
      "source": "sources/$archive",
      "source_sha256": "$(shasum -a 256 "$sources/$archive" | cut -d' ' -f1)"
    }
EOF
}
cat > "$out/manifest.json" <<EOF
{
  "target": "macos-arm64",
  "min_macos": "$MACOS_MIN",
  "components": [
$(component openconnect "$OPENCONNECT_VERSION" "LGPL-2.1-only AND BSD-2-Clause" "$openconnect_src" libopenconnect),
$(component gnutls "$GNUTLS_VERSION" "LGPL-2.1-or-later" "${GNUTLS_URL##*/}" libgnutls),
$(component nettle "$NETTLE_VERSION" "LGPL-3.0-or-later OR GPL-2.0-or-later" "${NETTLE_URL##*/}" libnettle libhogweed),
$(component gmp "$GMP_VERSION" "LGPL-3.0-or-later OR GPL-2.0-or-later" "${GMP_URL##*/}" libgmp)
  ],
  "openconnect_commit": "$OPENCONNECT_COMMIT",
  "built_with": {
    "macos": "$(sw_vers -productVersion)",
    "sdk": "$(xcrun --show-sdk-version)",
    "compiler": "$(cc --version | head -1)",
    "autoconf": "$(autoconf --version | head -1)",
    "automake": "$(automake --version | head -1)",
    "libtool": "$(glibtool --version | head -1)"
  }
}
EOF
cat "$out/manifest.json"
