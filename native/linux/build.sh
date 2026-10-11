#!/usr/bin/env bash
# Builds libopenconnect for Linux x64 into the given folder.
# Run as root in the ubuntu:22.04 image pinned in .github/workflows/native-linux.yml.
set -euo pipefail

OPENCONNECT_VERSION=9.21
OPENCONNECT_COMMIT=8b702bf2dbaf11302ed98629214b1df5d50a12aa
OPENCONNECT_URL=https://gitlab.com/openconnect/openconnect.git

LIBXML2_VERSION=2.15.4
LIBXML2_SHA256=98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821
LIBXML2_URL=https://download.gnome.org/sources/libxml2/2.15/libxml2-$LIBXML2_VERSION.tar.xz

# The only shared libraries the result may need. All four have the same
# soname on every supported system.
ALLOWED_NEEDED="libc.so.6 libm.so.6 libgnutls.so.30 libz.so.1"

[ $# -eq 1 ] || { echo "usage: build.sh <output-dir>" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)
work=$(mktemp -d)

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    autoconf automake ca-certificates curl gcc git libc6-dev libgnutls28-dev \
    libtool make pkg-config xz-utils zlib1g-dev

mkdir -p "$out/lib/pkgconfig" "$out/include" "$out/source" \
    "$out/licenses/openconnect" "$out/licenses/json-parser" "$out/licenses/libxml2"

# libxml2, static. It is linked into libopenconnect because its soname is
# not the same on every supported system.
cd "$work"
curl -fsSLO "$LIBXML2_URL"
echo "$LIBXML2_SHA256  libxml2-$LIBXML2_VERSION.tar.xz" | sha256sum -c -
cp "libxml2-$LIBXML2_VERSION.tar.xz" "$out/source/"
tar -xf "libxml2-$LIBXML2_VERSION.tar.xz"
cd "libxml2-$LIBXML2_VERSION"
./configure --prefix="$work/deps" --disable-shared --enable-static --with-pic \
    --without-python --without-zlib --without-lzma --without-icu \
    --without-http --without-modules --without-readline \
    CFLAGS=-O2
make -j"$(nproc)"
make install
cp Copyright "$out/licenses/libxml2/"

# openconnect, from the pinned commit. It is built in the git checkout
# because its version string comes from `git describe`.
cd "$work"
git init -q openconnect
cd openconnect
tag="v$OPENCONNECT_VERSION"
git fetch -q --depth 1 "$OPENCONNECT_URL" "refs/tags/$tag:refs/tags/$tag"
git checkout -q "$tag"
if [ "$(git rev-parse HEAD)" != "$OPENCONNECT_COMMIT" ]; then
    echo "error: $tag is $(git rev-parse HEAD), expected $OPENCONNECT_COMMIT" >&2
    exit 1
fi
git archive --format=tar.gz --prefix="openconnect-$OPENCONNECT_VERSION/" \
    -o "$out/source/openconnect-$OPENCONNECT_VERSION.tar.gz" HEAD
cp COPYING.LGPL "$out/licenses/openconnect/"
cp json/LICENSE "$out/licenses/json-parser/"

./autogen.sh
# The two ac_cv_func settings turn off features that have no configure switch
# and would link more libraries directly: PKCS#11 smart cards (p11-kit) and
# the external-browser login (nettle, hogweed, gmp).
PKG_CONFIG_PATH="$work/deps/lib/pkgconfig" ./configure --prefix="$work/stage" \
    --disable-static --disable-nls --disable-docs \
    --with-gnutls --without-lz4 --without-libproxy --without-stoken \
    --without-libpcsclite --without-libpskc --without-gssapi \
    --without-external-browser --with-vpnc-script=/etc/vpnc/vpnc-script \
    ac_cv_func_gnutls_pkcs11_add_provider=no \
    ac_cv_func_gnutls_hkdf_expand=no \
    CFLAGS=-O2 LDFLAGS=-Wl,-z,defs
make -j"$(nproc)" libopenconnect.la
make install-libLTLIBRARIES install-includeHEADERS install-pkgconfigDATA

cd "$work/stage"
strip --strip-unneeded lib/libopenconnect.so.5
cp -a lib/libopenconnect.so* "$out/lib/"
cp include/openconnect.h "$out/include/"
# Make the pkg-config file work wherever the folder is unpacked, and drop the
# lines that only matter for static linking.
sed -e 's|^prefix=.*|prefix=${pcfiledir}/../..|' \
    -e '/^Requires\.private:/d' -e '/^Libs\.private:/d' \
    lib/pkgconfig/openconnect.pc > "$out/lib/pkgconfig/openconnect.pc"

# Checks on the result.
lib="$out/lib/libopenconnect.so.5"
needed=$(objdump -p "$lib" | awk '$1 == "NEEDED" { print $2 }')
echo "NEEDED:" $needed
for n in $needed; do
    case " $ALLOWED_NEEDED " in
        *" $n "*) ;;
        *) echo "error: unexpected dependency $n" >&2; exit 1 ;;
    esac
done
if nm -D --defined-only "$lib" | awk '{ print $NF }' | grep -Ev '^(openconnect_|OPENCONNECT_)'; then
    echo "error: the symbols above should not be exported" >&2
    exit 1
fi
echo "Highest GLIBC symbol versions required:"
objdump -T "$lib" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 3
glibc=$(objdump -T "$lib" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1)
gnutls=$(dpkg-query -W -f '${Version}' libgnutls28-dev)

json_list() {
    local sep="" item
    for item in "$@"; do
        printf '%s"%s"' "$sep" "$item"
        sep=", "
    done
}

cat > "$out/manifest.json" <<EOF
{
  "target": "x86_64-unknown-linux-gnu",
  "built_on": "ubuntu:22.04",
  "components": [
    {
      "name": "openconnect",
      "version": "$OPENCONNECT_VERSION",
      "commit": "$OPENCONNECT_COMMIT",
      "licence": "LGPL-2.1-only",
      "licence_file": "licenses/openconnect/COPYING.LGPL",
      "source": "source/openconnect-$OPENCONNECT_VERSION.tar.gz",
      "patches": [],
      "files": ["lib/libopenconnect.so.5"]
    },
    {
      "name": "json-parser",
      "version": "bundled with openconnect $OPENCONNECT_VERSION",
      "licence": "BSD-2-Clause",
      "licence_file": "licenses/json-parser/LICENSE",
      "source": "source/openconnect-$OPENCONNECT_VERSION.tar.gz",
      "linked": "statically into libopenconnect"
    },
    {
      "name": "libxml2",
      "version": "$LIBXML2_VERSION",
      "sha256": "$LIBXML2_SHA256",
      "licence": "MIT",
      "licence_file": "licenses/libxml2/Copyright",
      "source": "source/libxml2-$LIBXML2_VERSION.tar.xz",
      "patches": [],
      "linked": "statically into libopenconnect"
    }
  ],
  "system": {
    "needed": [$(json_list $needed)],
    "max_glibc_symbol": "$glibc",
    "built_against_gnutls": "$gnutls",
    "deb_depends": ["libc6 (>= ${glibc#GLIBC_})", "libgnutls30 (>= 3.7.3)", "zlib1g"],
    "rpm_requires": ["glibc >= ${glibc#GLIBC_}", "gnutls >= 3.7.3", "zlib"]
  }
}
EOF
cat "$out/manifest.json"
ls -lR "$out"
