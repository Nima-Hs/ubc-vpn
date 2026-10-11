#!/usr/bin/env bash
# Builds GnuTLS from source into cache/gnutls. Called by build.sh.
#
# The result is reused while common.sh, this script, the patches and the lock
# files are unchanged, so anything that should cause a rebuild belongs in one
# of those. A reused build is never marked shippable (see tests/approve.sh).
set -euo pipefail
. "$(dirname "$0")/common.sh"
require_ucrt64

# The GnuTLS maintainer whose signature the release must carry: Zoltan
# Fridrich. The key is in keys/ and in the keyring gnutls.org publishes for its
# releases (https://www.gnutls.org/gnutls-release-keyring.gpg). It expires on
# 2027-01-01.
SIGNER=5D46CB0F763405A7053556F47A75A648B3F9220C

tarball=$GNUTLS_TARBALL
key=$(cat "$here"/common.sh "$here"/gnutls.sh "$here"/patches/gnutls/*.patch \
    "$here"/packages.lock "$here"/tools.lock "$here"/sources.lock | sha256sum | cut -d' ' -f1)
if [ "$(cat "$gnutls/.key" 2>/dev/null)" = "$key" ]; then
    echo "GnuTLS $GNUTLS_VERSION: reusing the build in $gnutls"
    exit 0
fi

build=$work/gnutls
rm -rf "$gnutls" "$build"
mkdir -p "$gnutls/build-info" "$build/gnupg"

curl -fsSL -o "$gnutls/$tarball" "$GNUTLS_URL"
[ "$(sha256 "$gnutls/$tarball")" = "$(locked_sha sources.lock "$tarball")" ] ||
    die "$tarball does not have the SHA-256 in sources.lock"

# Releases have a second signature by a key gnutls.org does not publish. gpg
# cannot check it and exits with an error, so go by what it reports about ours.
curl -fsSL -o "$build/$tarball.sig" "$GNUTLS_URL.sig"
gpg --homedir "$build/gnupg" --no-permission-warning --batch --quiet --import "$here/keys/gnutls-release.asc"
verdict=$(gpg --homedir "$build/gnupg" --no-permission-warning --batch --status-fd 1 \
    --verify "$build/$tarball.sig" "$gnutls/$tarball" 2>/dev/null || true)
grep -q "^\[GNUPG:\] VALIDSIG $SIGNER " <<<"$verdict" ||
    die "$tarball is not signed by $SIGNER:"$'\n'"$verdict"

tar -xf "$gnutls/$tarball" -C "$build"
cd "$build/gnutls-$GNUTLS_VERSION"
for p in "$here"/patches/gnutls/*.patch; do
    patch -p1 <"$p"
done

# The library only, with every optional dependency off, so that it needs
# nothing but Nettle and GMP. What matters for safety:
#   --with-system-priority-file=   (empty) builds GnuTLS without a system
#                                  configuration file. Upstream would still
#                                  read one named by an environment variable;
#                                  the patch in patches/gnutls removes that.
#   --without-p11-kit              compiles PKCS#11 out, and with it the
#                                  module configuration files.
#   --disable-nls                  no message catalogues to look for.
#   --without-default-trust-store-file  trusted certificates come from Windows.
# The gl_cv_ settings and the two extra C flags are what MSYS2's own recipe needs
# to build GnuTLS with MinGW. -ffile-prefix-map keeps this folder's path out
# of the DLL.
./configure --prefix="$(cygpath -m "$gnutls")" \
    --enable-shared --disable-static \
    --disable-doc --disable-tools --disable-tests --disable-cxx --disable-nls \
    --disable-libdane --disable-rpath \
    --with-included-libtasn1 --with-included-unistring \
    --without-p11-kit --without-tpm --without-tpm2 --without-idn \
    --without-zlib --without-brotli --without-zstd \
    --without-default-trust-store-file \
    --with-system-priority-file= \
    gl_cv_have_weak=no gl_cv_double_slash_root=yes \
    CFLAGS="-O2 -D_POSIX_C_SOURCE -Wno-int-conversion -ffile-prefix-map=$(cygpath -m "$build")=."
# build.sh checks in this what configure decided, on every run.
cp config.h "$gnutls/build-info/"
make -j"$(nproc)"

# licences.txt takes the MinGW headers under ZPL-2.1. That holds only while no
# header from their LGPL part, the DDK, is compiled in.
included=$(find . \( -name '*.Plo' -o -name '*.Po' \) -exec cat {} +)
grep -q '/include/windows\.h' <<<"$included" || die "the compiler's dependency files are missing"
! grep -q '/ddk/' <<<"$included" || die "a DDK header is compiled in; review the headers entry in licences.txt"

make install
echo "$key" >"$gnutls/.key"
# Tells build.sh that this run built the library, not an earlier one.
touch "$work/gnutls-built-in-this-run"
