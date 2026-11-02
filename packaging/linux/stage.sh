#!/usr/bin/env bash
# Builds and gathers our part of what the Linux packages install beside the
# app, for electron-builder to pick up (app/electron-builder.linux.yml). Run
# on Linux, from the repository root:
#
#   packaging/linux/stage.sh <native-folder> <native-build> <sources-archive>
#
# <native-folder> is an unpacked libopenconnect-linux-x64 build
# (native/linux/build.sh). <native-build> is the address of the run that
# built it, recorded in SOURCES.txt and the sources archive so a release
# says which build it shipped. <sources-archive> is where the exact source
# of the bundled LGPL library is written, as a .tar.gz, for publishing
# beside the packages.
#
# It writes app/stage/:
#   bin/          ubc-vpn and ubc-vpn-service, built in release mode with the
#                 real engine, and libopenconnect.so.5, the file itself
#   licenses/     the library's licence texts (native/), and SOURCES.txt
#   policy.json   the policy `ubc-vpn-service install` copies to /etc/ubc-vpn
#   links/        ubc-vpn, the link the packages install as /usr/bin/ubc-vpn
#
# It stops if the library differs from the SHA-256 its manifest records.
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
library="$native/lib/libopenconnect.so.5"

# The library is the one its manifest records, which is what ties it to the
# source published for it.
want=$(node -e 'let s="";process.stdin.on("data",(d)=>(s+=d)).on("end",()=>console.log(JSON.parse(s).components.find((c)=>c.name==="openconnect").file_sha256))' < "$native/manifest.json")
have=$(sha256sum "$library" | cut -d ' ' -f 1)
[ "$want" = "$have" ] || {
  echo "$library is not the library its manifest records" >&2
  exit 1
}

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/licenses/native" "$stage/links"

# The two programs, each built by itself with -p and the real engine only,
# as packaging/windows/stage.sh builds them: built together, the service
# would get the keyring feature only the client enables. No rpath or
# runpath: the engine loads the library by its full path beside the
# program, and an rpath would make the loader search a folder before the
# service has checked it. RUSTFLAGS is emptied so nothing adds one.
for package in ubc-vpn-service ubc-vpn-cli; do
  RUSTFLAGS="" UBC_VPN_NATIVE_DIR="$native" cargo build --locked --release -p "$package" --features real-engine
done
cp "$root/target/release/ubc-vpn-service" "$root/target/release/ubc-vpn" "$stage/bin/"
# The file itself, never a link: the service refuses a link in its folder.
cp -L "$library" "$stage/bin/libopenconnect.so.5"

cp -R "$native/licenses/." "$stage/licenses/native/"
cp "$root/packaging/windows/policy.json" "$stage/policy.json"
# /usr/bin/ubc-vpn: the client by its own command name (decision G19). The
# client finds its own folder through the link.
ln -s "/opt/UBC VPN/resources/bin/ubc-vpn" "$stage/links/ubc-vpn"

version=$(cd "$root" && node -p "require('./app/package.json').version")
cat > "$stage/licenses/SOURCES.txt" <<EOF
The exact source of the LGPL library installed with UBC VPN $version
(libopenconnect.so.5: openconnect under the GNU Lesser General Public
License 2.1, with json-parser and libxml2 built into it), with our patch
and the build script, is published with each release of UBC VPN, beside
its packages, as

  ubc-vpn-$version-linux-x64-sources.tar.gz

at https://github.com/Nima-Hs/ubc-vpn/releases. Their licence texts are in
native/ in this folder.

The library was built by:
$build
EOF
mkdir -p "$(dirname "$sources")"
echo "Built by: $build" > "$native/native-build.txt"
tar -czf "$sources" -C "$native" source licenses manifest.json native-build.txt

# Folders and programs 755, every other file 644, whatever the umask: the
# packages install them as they are here.
find "$stage" -type d -exec chmod 755 {} +
find "$stage" -type f -exec chmod 644 {} +
chmod 755 "$stage/bin/ubc-vpn-service" "$stage/bin/ubc-vpn"

echo "Staged in $stage:"
(cd "$stage" && find . ! -type d | sort)
