#!/usr/bin/env bash
# Builds and gathers our part of what the Windows setup program installs
# beside the app, for electron-builder to pick up (app/electron-builder.yml).
# Run from Git Bash on Windows, from the repository root:
#
#   packaging/windows/stage.sh <native-folder> <native-run> <recipe-folder> <sources-archive>
#
# <native-folder> is an unpacked libopenconnect-windows-x64 artifact from a
# Native library run on main; the workflow fetching it checks its commit is
# on main (see CONTRIBUTING.md). <native-run> is that run's ID, recorded in
# SOURCES.txt and the sources archive so a release says which run it
# shipped. <recipe-folder> is native/windows as it is at the commit the
# artifact's manifest names, which the artifact's recipe must match.
# <sources-archive> is where the exact source of the bundled LGPL libraries
# is written, as a .tar.gz, for publishing beside the setup program.
#
# It writes app/stage/:
#   bin/          ubc-vpn.exe and ubc-vpn-service.exe, built in release mode
#                 with the real engine, and the libraries from the artifact
#   licenses/     their licence texts (native/), and SOURCES.txt
#   policy.json   the policy the service installs (packaging/windows)
#
# Then packaging/windows/stage-redist.sh adds what is not ours to pass on by
# itself: Wintun and Microsoft's Visual C++ runtime, with their licences,
# and the licence page. Those two may only be distributed inside our setup
# program, so they are never kept as a CI artifact; this part may be.
#
# It stops at anything unexpected: an artifact not marked shippable, a
# library or source archive that differs from the artifact's manifest.json
# or is not listed in it, a recipe that differs from <recipe-folder>
# (check-native.mjs), or a set of libraries other than native/windows/dlls.txt.
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 <native-folder> <native-run> <recipe-folder> <sources-archive>" >&2
  exit 2
fi
native=$(cd "$1" && pwd)
run=$2
recipe=$3
sources=$4
[[ $run =~ ^[0-9]+$ ]] || {
  echo "the native run ID must be a number: $run" >&2
  exit 2
}
root=$(cd "$(dirname "$0")/../.." && pwd)
stage="$root/app/stage"

# The artifact: marked shippable by its own workflow's last job, and with
# exactly the libraries native/windows/dlls.txt lists.
shippable=$(node -e 'let s="";process.stdin.on("data",(d)=>(s+=d)).on("end",()=>console.log(JSON.parse(s).shippable === true))' < "$native/manifest.json")
[ "$shippable" = true ] || {
  echo "$native is not marked shippable" >&2
  exit 1
}
# Each library and source archive is the one its manifest records: the
# manifest is what ties a shipped library to the source published for it.
# The recipe is this repository's at the commit the manifest names.
node "$root/packaging/windows/check-native.mjs" "$native" "$recipe"
expected=$(sed -n 's/^\([A-Za-z0-9_.-]*\.dll\) .*/\1/p' "$root/native/windows/dlls.txt" | sort)
found=$(cd "$native/bin" && ls -- *.dll | sort)
if [ "$expected" != "$found" ]; then
  echo "the artifact's libraries differ from native/windows/dlls.txt:" >&2
  diff <(echo "$expected") <(echo "$found") >&2 || true
  exit 1
fi

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/licenses/native"

# The two programs, each built by itself and with the real engine only: a
# release must never contain dev mode or the fakes (see ci.yml).
#
# Each is built on its own, with -p, and never with --workspace or both
# packages in one command: Cargo then gives every package the features
# any of them asks for, and the service would be built with the keyring
# code only the client enables.
for package in ubc-vpn-service ubc-vpn-cli; do
  UBC_VPN_NATIVE_DIR="$native" cargo build --locked --release -p "$package" --features real-engine
done
service_exe="$root/target/release/ubc-vpn-service.exe"
client_exe="$root/target/release/ubc-vpn.exe"

# The service runs as SYSTEM and never touches a user's keyring: no
# keyring code may be in it. Checked in the program that ships, by the
# Credential Manager functions the keyring calls and the names of the
# keyring crates. The client must hold them, or this check proves nothing.
keyring_marks=(CredReadW CredWriteW CredDeleteW keyring zbus)
for mark in "${keyring_marks[@]}"; do
  if grep -q -a -F -- "$mark" "$service_exe"; then
    echo "the service holds keyring code: $mark found in $service_exe" >&2
    exit 1
  fi
done
grep -q -a -F -- CredReadW "$client_exe" || {
  echo "the client holds no keyring code, so the service check above proves nothing" >&2
  exit 1
}
cp "$service_exe" "$client_exe" "$stage/bin/"

cp "$native"/bin/*.dll "$stage/bin/"
cp -R "$native/licenses/." "$stage/licenses/native/"

cp "$root/packaging/windows/policy.json" "$stage/policy.json"

# Where the LGPL libraries' source is: published beside the setup program.
version=$(cd "$root" && node -p "require('./app/package.json').version")
cat > "$stage/licenses/SOURCES.txt" <<EOF
The exact source of the LGPL libraries installed with UBC VPN $version
(libopenconnect-5.dll, libgnutls-30.dll, libnettle-9.dll, libhogweed-7.dll,
libgmp-10.dll, libiconv-2.dll), with our patches and the build recipe, is
published with each release of UBC VPN, beside its setup program, as

  ubc-vpn-$version-windows-x64-sources.tar.gz

at https://github.com/Nima-Hs/ubc-vpn/releases. It is built in the same
run as the setup program. Their licence texts are in native/ in this folder.

The libraries come from run $run of the Native library (Windows) workflow:
https://github.com/Nima-Hs/ubc-vpn/actions/runs/$run
EOF
mkdir -p "$(dirname "$sources")"
echo "Run $run of the Native library (Windows) workflow: https://github.com/Nima-Hs/ubc-vpn/actions/runs/$run" >"$native/native-run.txt"
# --force-local: a Windows path such as D:... is a file, not a remote host.
tar --force-local -czf "$sources" -C "$native" source licenses manifest.json build-packages.txt native-run.txt

echo "Staged in $stage:"
(cd "$stage" && find . -type f | sort)
