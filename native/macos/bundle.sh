#!/bin/bash
# Turns what build.sh produced into a folder that can be moved anywhere:
# libopenconnect and the libraries it needs, made relocatable and signed,
# with their licences, their sources and a manifest. Fails if any library
# does not meet the rules checked below.
#
# Usage: bundle.sh <work-dir> <out-dir>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=versions.env
. "$here/versions.env"

export DEVELOPER_DIR=$XCODE/Contents/Developer
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Recorded in the manifest: the commit of this repository the libraries were
# built from. Whoever uses the output checks that it is a commit on main.
: "${SOURCE_COMMIT:?set SOURCE_COMMIT to the commit of this repository}"
if ! [[ $SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]]; then
    echo "FAIL: SOURCE_COMMIT is not a full commit hash." >&2
    exit 1
fi

work=$(cd "${1:?usage: bundle.sh <work-dir> <out-dir>}" && pwd)
prefix=$work/prefix
sources=$work/sources
rm -rf "${2:?usage: bundle.sh <work-dir> <out-dir>}"
mkdir -p "$2/lib/pkgconfig" "$2/include" "$2/licenses" "$2/sources/recipe"
out=$(cd "$2" && pwd)

# The only parts of macOS the libraries may load.
system_libraries="/usr/lib/libSystem.B.dylib
/usr/lib/libiconv.2.dylib
/usr/lib/libxml2.2.dylib
/usr/lib/libz.1.dylib
/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
/System/Library/Frameworks/Security.framework/Versions/A/Security"

is_system() {
    grep -qxF "$1" <<< "$system_libraries"
}

# The libraries a file loads, one per line. For a library the list includes
# its own name.
loads() {
    otool -L "$1" | sed -n 's/^[[:space:]]*\(.*\) (compatibility version .*/\1/p'
}

# Copies a library and, in turn, everything it loads from our prefix.
collect() {
    local name=${1##*/} deps dep
    [ -f "$out/lib/$name" ] && return 0
    cp -L "$1" "$out/lib/$name"
    chmod 644 "$out/lib/$name"
    deps=$(loads "$1")
    while IFS= read -r dep; do
        case $dep in
            "$prefix"/*) collect "$dep" ;;
            *)
                if ! is_system "$dep"; then
                    echo "$name loads $dep, which is neither ours nor an expected system library." >&2
                    exit 1
                fi
                ;;
        esac
    done <<< "$deps"
}
collect "$prefix/lib/libopenconnect.5.dylib"

# Make each library findable next to the others instead of at its build path.
# Editing a library breaks its signature, and Apple silicon refuses to load
# unsigned code, so sign again (ad hoc) afterwards. Debug symbols go too:
# Nettle builds with them, and they record the build directory.
for lib in "$out"/lib/*.dylib; do
    strip -S "$lib"
    install_name_tool -id "@rpath/${lib##*/}" "$lib"
    deps=$(loads "$lib")
    while IFS= read -r dep; do
        case $dep in
            "$prefix"/*) install_name_tool -change "$dep" "@loader_path/${dep##*/}" "$lib" ;;
        esac
    done <<< "$deps"
    codesign --force --sign - "$lib"
done

# Check every library before anything else is written.
failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=1
}
for lib in "$out"/lib/*.dylib; do
    name=${lib##*/}
    archs=$(lipo -archs "$lib")
    [ "$archs" = arm64 ] || fail "$name is $archs, not arm64 only"

    minos=$(otool -l "$lib" | awk '/LC_BUILD_VERSION/ { found = 1 } found && $1 == "minos" { print $2; exit }')
    [ "$minos" = "$MACOS_MIN" ] || fail "$name needs macOS $minos, not $MACOS_MIN"

    # A weak import is a function the SDK has but the oldest macOS may not.
    # It loads as a null pointer there and crashes when called.
    symbols=$(nm -m "$lib")
    if grep 'undefined) weak external' <<< "$symbols" >&2; then
        fail "$name has the weak imports above"
    fi

    header=$(otool -hv "$lib")
    grep -q TWOLEVEL <<< "$header" || fail "$name uses a flat namespace"

    codesign --verify --strict "$lib" || fail "$name has no valid signature"

    commands=$(otool -l "$lib")
    if grep -q LC_RPATH <<< "$commands"; then
        fail "$name carries a search path of its own"
    fi

    deps=$(loads "$lib")
    while IFS= read -r dep; do
        case $dep in
            "@rpath/$name" | @loader_path/lib*.dylib) [ -f "$out/lib/${dep##*/}" ] || fail "$name loads $dep, which is not in the folder" ;;
            *) is_system "$dep" || fail "$name loads $dep" ;;
        esac
    done <<< "$deps"

    if grep -q "$work" "$lib"; then
        fail "$name contains the build directory:"
        grep -a -o "[[:print:]]*$work[[:print:]]*" "$lib" | sort -u | head -5 >&2
    fi

    echo "$name: arm64, macOS $minos, no weak imports, signed; loads:"
    sed 's/^/    /' <<< "$deps"
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

# One call per shipped component: copies its source archive and licence
# texts (the LGPL asks us to ship the source we built from) and adds it to
# the manifest.
components=""
listed=0
component() { # <name> <version> <licence> <url> "<licence files>" <library>...
    local name=$1 version=$2 licence=$3 archive=${4##*/} files=$5 file lib libs="" sha256
    shift 5
    cp "$sources/$archive" "$out/sources/"
    sha256=$(shasum -a 256 "$sources/$archive" | cut -d' ' -f1)

    mkdir -p "$out/licenses/$name"
    for file in $files; do
        tar -xOf "$sources/$archive" "$name-$version/$file" > "$out/licenses/$name/${file//\//-}"
    done

    for lib in "$@"; do
        [ -f "$out/lib/$lib" ]
        libs="$libs${libs:+, }\"lib/$lib\""
        listed=$((listed + 1))
    done

    components="$components${components:+,
}    {
      \"name\": \"$name\",
      \"version\": \"$version\",
      \"licence\": \"$licence\",
      \"min_macos\": \"$MACOS_MIN\",
      \"libraries\": [$libs],
      \"source\": \"sources/$archive\",
      \"source_sha256\": \"$sha256\"
    }"
}
component openconnect "$OPENCONNECT_VERSION" "LGPL-2.1-only AND BSD-2-Clause" "$OPENCONNECT_URL" \
    "COPYING.LGPL json/LICENSE" libopenconnect.5.dylib
component gnutls "$GNUTLS_VERSION" "LGPL-2.1-or-later" "$GNUTLS_URL" \
    "COPYING.LESSERv2" libgnutls.30.dylib
component nettle "$NETTLE_VERSION" "LGPL-3.0-or-later OR GPL-2.0-or-later" "$NETTLE_URL" \
    "COPYING.LESSERv3 COPYINGv3 COPYINGv2" libnettle.9.dylib libhogweed.7.dylib
component gmp "$GMP_VERSION" "LGPL-3.0-or-later OR GPL-2.0-or-later" "$GMP_URL" \
    "COPYING.LESSERv3 COPYINGv3 COPYINGv2" libgmp.10.dylib

# Every library in the folder must belong to a component above.
shipped=$(find "$out/lib" -type f -name '*.dylib' | wc -l)
if [ "$shipped" -ne "$listed" ]; then
    echo "FAIL: $shipped libraries in the folder, $listed in the manifest." >&2
    exit 1
fi

cp "$here/build.sh" "$here/bundle.sh" "$here/versions.env" "$out/sources/recipe/"

macos=$(sw_vers -productVersion)
xcode=$(xcodebuild -version | tr '\n' ' ' | sed 's/ $//')
sdk=$(xcrun --show-sdk-version)
compiler=$(cc --version | sed -n 1p)
make=$(make --version | sed -n 1p)
m4=$(m4 --version | sed -n 1p)
cat > "$out/manifest.json" <<EOF
{
  "target": "macos-arm64",
  "min_macos": "$MACOS_MIN",
  "recipe": {
    "repository": "https://github.com/Nima-Hs/ubc-vpn",
    "commit": "$SOURCE_COMMIT",
    "files": "sources/recipe/"
  },
  "components": [
$components
  ],
  "openconnect_tag_commit": "$OPENCONNECT_COMMIT",
  "built_with": {
    "macos": "$macos",
    "xcode": "$xcode",
    "sdk": "$sdk",
    "compiler": "$compiler",
    "make": "$make",
    "m4": "$m4",
    "pkgconf": "$PKGCONF_VERSION",
    "pkgconf_source": "$PKGCONF_URL",
    "pkgconf_source_sha256": "$PKGCONF_SHA256"
  }
}
EOF
cat "$out/manifest.json"
