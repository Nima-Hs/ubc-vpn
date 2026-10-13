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
if [ ! -d "$XCODE/Contents/Developer" ]; then
    echo "The pinned Xcode is not installed at $XCODE." >&2
    exit 1
fi

mkdir -p "${1:?usage: build.sh <work-dir>}"
work=$(cd "$1" && pwd)
prefix=$work/prefix
sources=$work/sources
src=$work/src
mkdir -p "$prefix" "$sources" "$src"

# Only macOS, the pinned Xcode and what this script builds take part.
# Homebrew is not on the path.
export DEVELOPER_DIR=$XCODE/Contents/Developer
export PATH=$prefix/bin:/usr/bin:/bin:/usr/sbin:/sbin

# The SDK is newer than the oldest macOS we support. Turn the use of any
# function that macOS lacks into an error rather than a warning.
export MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN
export CFLAGS="-O2 -mmacosx-version-min=$MACOS_MIN -Werror=unguarded-availability-new"
export CPPFLAGS="-I$prefix/include"
export LDFLAGS="-L$prefix/lib -mmacosx-version-min=$MACOS_MIN"
# Look for libraries in our own prefix only.
export PKG_CONFIG=$prefix/bin/pkgconf
export PKG_CONFIG_LIBDIR=$prefix/lib/pkgconfig
unset PKG_CONFIG_PATH

jobs=$(sysctl -n hw.ncpu)

# Downloads one source archive, or reuses it, and checks it either way.
fetch() { # <url> <sha256>
    local file=$sources/${1##*/}
    [ -f "$file" ] || curl -fsSL --retry 3 -o "$file" "$1"
    echo "$2  $file" | shasum -a 256 -c -
}

# Builds one component, unless an earlier run already did, with the patches
# in patches/<name>/ applied. A change to its patches is a new build.
component() { # <name> <version> <url> <sha256> <check|nocheck> [configure options]
    local name=$1 version=$2 url=$3 sha256=$4 check=$5 patch patched
    shift 5
    fetch "$url" "$sha256"

    # A component with no patches has no such files, and that is not a failure.
    patched=$(cat "$here/patches/$name"/*.patch 2>/dev/null | shasum -a 256 | cut -c1-12 || true)
    local stamp=$prefix/.built-$name-$version-$patched
    [ -f "$stamp" ] && return 0

    rm -rf "$src/$name-$version"
    tar -xf "$sources/${url##*/}" -C "$src"
    for patch in "$here/patches/$name"/*.patch; do
        [ -f "$patch" ] || continue
        patch -p1 -d "$src/$name-$version" < "$patch"
    done
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

component pkgconf "$PKGCONF_VERSION" "$PKGCONF_URL" "$PKGCONF_SHA256" nocheck

# --build without a CPU model stops GMP tuning itself for the build machine.
component gmp "$GMP_VERSION" "$GMP_URL" "$GMP_SHA256" check \
    --build="aarch64-apple-darwin$(uname -r)"

component nettle "$NETTLE_VERSION" "$NETTLE_URL" "$NETTLE_SHA256" check \
    --disable-documentation --disable-openssl

# Library only, with every optional dependency switched off. With no trust
# store file, GnuTLS takes the system's trusted certificates from the Keychain.
# The priority file is given an absolute path so that the build directory is
# not compiled in.
component gnutls "$GNUTLS_VERSION" "$GNUTLS_URL" "$GNUTLS_SHA256" nocheck \
    --disable-doc --disable-tools --disable-tests --disable-cxx --disable-nls \
    --disable-libdane \
    --with-included-libtasn1 --with-included-unistring \
    --without-p11-kit --without-tpm --without-tpm2 --without-idn \
    --without-zlib --without-brotli --without-zstd \
    --without-default-trust-store-file \
    --with-system-priority-file=/etc/gnutls/config

# libxml2 and zlib are the system's; the SDK has no pkg-config file for
# libxml2, so say where it is. strchrnul exists only from macOS 15.4, so make
# openconnect use its own. The vpnc-script path is used by the command-line
# client only, which is built but not shipped; the library never runs it.
# No external-browser login: no browser to start, and with the HKDF check
# answered "no" no HPKE, so a gateway's single sign-on form fails at once
# instead of the library listening on a local port for a browser.
sdk=$(xcrun --show-sdk-path)
component openconnect "$OPENCONNECT_VERSION" "$OPENCONNECT_URL" "$OPENCONNECT_SHA256" nocheck \
    --with-gnutls --disable-nls --disable-docs \
    --without-libproxy --without-stoken --without-libpskc \
    --without-libpcsclite --without-lz4 --without-gssapi \
    --without-external-browser --with-vpnc-script=/nonexistent/vpnc-script \
    ac_cv_func_strchrnul=no ac_cv_func_gnutls_hkdf_expand=no \
    LIBXML2_CFLAGS="-I$sdk/usr/include/libxml2" LIBXML2_LIBS=-lxml2
# What the build above configured and compiled. A cached build was checked
# when it was made, with the same options: the options are in this file,
# which is part of the cache key.
config=$src/openconnect-$OPENCONNECT_VERSION/config.h
if [ -f "$config" ] && grep -qE '^#define (HAVE_HPKE_SUPPORT|DEFAULT_EXTERNAL_BROWSER)' "$config"; then
    echo "The openconnect build has the external-browser login." >&2
    exit 1
fi
