#!/usr/bin/env bash
# For development on Windows: puts the libraries a real-engine build of the
# command-line client and the service loads beside those programs, as the
# installer will. Run from Git Bash:
#
#   native/windows/stage.sh <native-folder> <program-folder>
#
# <native-folder> is an unpacked libopenconnect-windows-x64 artifact from a
# Native library run on main (see CONTRIBUTING.md). <program-folder> holds
# ubc-vpn.exe and ubc-vpn-service.exe, such as target/debug.
#
# Also downloads the Wintun pinned in wintun.pin, checks it against the
# pinned checksum, and puts its wintun.dll there. That copy is for your own
# machine: Wintun's licence lets it be passed on only inside our installer.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <native-folder> <program-folder>" >&2
  exit 2
fi
native=$1
programs=$2
here=$(cd "$(dirname "$0")" && pwd)

[ -f "$native/bin/libopenconnect-5.dll" ] || {
  echo "$native is not an unpacked libopenconnect-windows-x64 artifact" >&2
  exit 1
}
[ -d "$programs" ] || { echo "$programs is not a folder" >&2; exit 1; }

cp "$native"/bin/*.dll "$programs/"

mapfile -t pin < "$here/wintun.pin"
pin=("${pin[@]%$'\r'}")
[ "${#pin[@]}" -eq 2 ]
[[ ${pin[0]} =~ ^WINTUN_URL=(https://www\.wintun\.net/builds/[A-Za-z0-9._-]+\.zip)$ ]]
url=${BASH_REMATCH[1]}
[[ ${pin[1]} =~ ^WINTUN_SHA256=([0-9a-f]{64})$ ]]
sha=${BASH_REMATCH[1]}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSLo "$work/wintun.zip" "$url"
(cd "$work" && echo "$sha *wintun.zip" | sha256sum -c - && unzip -q wintun.zip)
cp "$work/wintun/bin/amd64/wintun.dll" "$programs/"

echo "Staged beside the programs in $programs:"
ls "$programs"/*.dll
