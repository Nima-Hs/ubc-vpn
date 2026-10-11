#!/bin/bash
# Builds libopenconnect and the libraries it needs from the sources pinned in
# versions.env, into <work-dir>/prefix. Run bundle.sh afterwards.
#
# Usage: build.sh <work-dir>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=versions.env
. "$here/versions.env"

if [ "$(uname -sm)" != "Darwin arm64" ]; then
    echo "This recipe is for macOS on Apple silicon." >&2
    exit 1
fi

mkdir -p "${1:?usage: build.sh <work-dir>}"
work=$(cd "$1" && pwd)
prefix=$work/prefix
sources=$work/sources
src=$work/src
mkdir -p "$prefix" "$sources" "$src"

export MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN
export CFLAGS="-O2 -mmacosx-version-min=$MACOS_MIN"
export CPPFLAGS="-I$prefix/include"
export LDFLAGS="-L$prefix/lib -mmacosx-version-min=$MACOS_MIN"
# Look for libraries in our own prefix only, so nothing from Homebrew is
# picked up by accident.
export PKG_CONFIG_LIBDIR=$prefix/lib/pkgconfig
unset PKG_CONFIG_PATH

jobs=$(sysctl -n hw.ncpu)

# Downloads one source archive, or reuses it, and checks it either way.
fetch() { # <url> <sha256>
    local file=$sources/${1##*/}
    [ -f "$file" ] || curl -fsSL --retry 3 -o "$file" "$1"
    echo "$2  $file" | shasum -a 256 -c -
}

# Builds one dependency, unless an earlier run already did.
dependency() { # <name> <version> <url> <sha256> <check|nocheck> [configure options]
    local name=$1 version=$2 url=$3 sha256=$4 check=$5
    shift 5
    fetch "$url" "$sha256"

    local stamp=$prefix/.built-$name-$version
    [ -f "$stamp" ] && return 0

    rm -rf "$src/$name-$version"
    tar -xf "$sources/${url##*/}" -C "$src"
    (
        cd "$src/$name-$version"
        ./configure --prefix="$prefix" --libdir="$prefix/lib" \
            --enable-shared --disable-static "$@"
        make -j"$jobs"
        [ "$check" = nocheck ] || make -j"$jobs" check
        make install
    )
    touch "$stamp"
}

# --build without a CPU model stops GMP tuning itself for the build machine.
dependency gmp "$GMP_VERSION" "$GMP_URL" "$GMP_SHA256" check \
    --build="aarch64-apple-darwin$(uname -r)"

dependency nettle "$NETTLE_VERSION" "$NETTLE_URL" "$NETTLE_SHA256" check \
    --disable-documentation --disable-openssl

# Library only, with every optional dependency switched off. With no trust
# store file, GnuTLS takes the system's trusted certificates from the Keychain.
# The priority file is given an absolute path so that the build directory is
# not compiled in.
dependency gnutls "$GNUTLS_VERSION" "$GNUTLS_URL" "$GNUTLS_SHA256" nocheck \
    --disable-doc --disable-tools --disable-tests --disable-cxx --disable-nls \
    --disable-libdane \
    --with-included-libtasn1 --with-included-unistring \
    --without-p11-kit --without-tpm --without-tpm2 --without-idn \
    --without-zlib --without-brotli --without-zstd \
    --without-default-trust-store-file \
    --with-system-priority-file=/etc/gnutls/config

# openconnect, from git. The build runs inside the checkout because that is
# how the library learns its own version (version.sh asks git).
tag=v$OPENCONNECT_VERSION
oc=$src/openconnect
rm -rf "$oc"
git init -q "$oc"
git -C "$oc" fetch -q --depth 1 "$OPENCONNECT_REPO" "refs/tags/$tag:refs/tags/$tag"
git -C "$oc" checkout -q "$tag"
if [ "$(git -C "$oc" rev-parse HEAD)" != "$OPENCONNECT_COMMIT" ]; then
    echo "Tag $tag is not at the pinned commit $OPENCONNECT_COMMIT." >&2
    exit 1
fi
# The exact source we build, kept to ship next to the library.
git -C "$oc" archive --prefix="openconnect-$OPENCONNECT_VERSION/" \
    -o "$sources/openconnect-$OPENCONNECT_VERSION.tar.gz" HEAD

sdk=$(xcrun --show-sdk-path)
(
    cd "$oc"
    ./autogen.sh
    # libxml2 and zlib are the system's; the SDK has no pkg-config file for
    # libxml2, so say where it is. The library never runs the vpnc-script
    # path given here: only the command-line client does, and it is not built.
    ./configure --prefix="$prefix" --libdir="$prefix/lib" \
        --with-gnutls --disable-nls --disable-docs \
        --without-libproxy --without-stoken --without-libpskc \
        --without-libpcsclite --without-lz4 --without-gssapi \
        --with-vpnc-script=/nonexistent/vpnc-script \
        LIBXML2_CFLAGS="-I$sdk/usr/include/libxml2" LIBXML2_LIBS=-lxml2
    make -j"$jobs" libopenconnect.la
    grep -q "\"$tag\"" version.c
    make install-libLTLIBRARIES install-includeHEADERS
)
