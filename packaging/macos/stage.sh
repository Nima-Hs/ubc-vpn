#!/usr/bin/env bash
# Builds and gathers our part of what the macOS package installs, for
# electron-builder to pick up (app/electron-builder.mac.yml). Run on macOS,
# from the repository root:
#
#   packaging/macos/stage.sh <native-folder> <native-build> <sources-archive>
#
# <native-folder> is an output folder of native/macos/bundle.sh. <native-build>
# is the address of the run that built it, recorded in SOURCES.txt and the
# sources archive so a release says which build it shipped. <sources-archive>
# is where the exact source of the bundled LGPL libraries is written, as a
# .tar.gz, for publishing beside the package.
#
# It writes app/stage/:
#   bin/          what the app holds, which runs as the user: the command-line
#                 client and the libraries it loads
#   licenses/     the libraries' licence texts (native/), and SOURCES.txt
#   pkg-scripts/  what the package's installer runs and copies, root's while it
#                 runs, and never in the app:
#                   postinstall  the script
#                   policy.json  the policy `ubc-vpn-service install` copies
#                   service/     the service, the libraries it loads, and the
#                                uninstall script
#
# Everything is a real file: the service refuses to run beside a link, and
# bundle.sh's link for the linker is left out. The ad-hoc signatures the linker
# and bundle.sh gave stay as they are (decision G21); nothing here signs.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <native-folder> <native-build> <sources-archive>" >&2
  exit 2
fi
native=$(cd "$1" && pwd)
build=$2
sources=$3
root=$(cd "$(dirname "$0")/../.." && pwd)
stage="$root/app/stage"
scripts="$stage/pkg-scripts"

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/licenses/native" "$scripts/service"

# The two programs, each built by itself with -p and the real engine only, as
# on the other systems: built together, the service would get the keyring
# feature only the client enables. No rpath: the engine loads the library by
# its full path beside the program, and a search path would make the loader
# look in a folder before the service has checked it. RUSTFLAGS is emptied so
# nothing adds one.
for package in ubc-vpn-service ubc-vpn-cli; do
  RUSTFLAGS="" UBC_VPN_NATIVE_DIR="$native" cargo build --locked --release -p "$package" --features real-engine
done
cp "$root/target/release/ubc-vpn" "$stage/bin/"
cp "$root/target/release/ubc-vpn-service" "$scripts/service/"
find "$native/lib" -maxdepth 1 -type f -name '*.dylib' -exec cp {} "$stage/bin/" \;
find "$native/lib" -maxdepth 1 -type f -name '*.dylib' -exec cp {} "$scripts/service/" \;

cp "$root/packaging/macos/scripts/postinstall" "$scripts/"
cp "$root/packaging/macos/uninstall.sh" "$scripts/service/"
cp "$root/packaging/windows/policy.json" "$scripts/policy.json"
cp -R "$native/licenses/." "$stage/licenses/native/"

version=$(cd "$root" && node -p "require('./app/package.json').version")
cat > "$stage/licenses/SOURCES.txt" <<EOF
The exact source of the LGPL libraries installed with UBC VPN $version, with
our patch and the build scripts, is published with each release of UBC VPN,
beside its package, as

  ubc-vpn-$version-macos-arm64-sources.tar.gz

at https://github.com/Nima-Hs/ubc-vpn/releases.

libopenconnect.5.dylib is openconnect under the GNU Lesser General Public
License 2.1, with json-parser (BSD-2-Clause) built into it. It loads GnuTLS
(libgnutls.30.dylib, LGPL-2.1-or-later), Nettle (libnettle.9.dylib and
libhogweed.7.dylib) and GMP (libgmp.10.dylib), each under the LGPL-3.0-or-later
or the GPL-2.0-or-later, and libxml2 and zlib from macOS itself. Their licence
texts are in native/ in this folder.

Each library is a separate file that can be replaced: in the app's
Contents/Resources/bin for the command-line client, and in
/Library/PrivilegedHelperTools/io.github.nima-hs.ubc-vpn for the service.

The libraries were built by:
$build
EOF
mkdir -p "$(dirname "$sources")"
echo "Built by: $build" > "$native/native-build.txt"
tar -czf "$sources" -C "$native" sources licenses manifest.json native-build.txt

# Folders and programs 755, every other file 644, whatever the umask: the
# package installs them as they are here. Modes do not touch a signature.
find "$stage" -type d -exec chmod 755 {} +
find "$stage" -type f -exec chmod 644 {} +
chmod 755 "$stage/bin/ubc-vpn" "$scripts/postinstall" \
  "$scripts/service/ubc-vpn-service" "$scripts/service/uninstall.sh"

if find "$stage" ! -type f ! -type d | grep .; then
  echo "The stage holds something that is not a file or a folder." >&2
  exit 1
fi
[ "$(find "$stage/bin" -name '*.dylib' | wc -l | tr -d ' ')" = 5 ] || {
  echo "The stage does not hold the five libraries." >&2
  exit 1
}

echo "Staged in $stage:"
(cd "$stage" && find . -type f | sort)
