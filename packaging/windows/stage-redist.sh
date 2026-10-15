#!/usr/bin/env bash
# Adds to app/stage/ (made by packaging/windows/stage.sh) what is not ours
# and may only be passed on inside our setup program: Wintun's wintun.dll
# and Microsoft's vcruntime140.dll, each as pinned and unmodified, with
# their licence texts, and the setup program's licence page. Run it in Git
# Bash on Windows, from the repository root, right before building the
# setup program, and never keep its output as a CI artifact:
#
#   packaging/windows/stage-redist.sh
#
# It stops if a download or the runtime differs from its pin.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
stage="$root/app/stage"
[ -f "$stage/bin/ubc-vpn-service.exe" ] || {
  echo "$stage is missing: run packaging/windows/stage.sh first" >&2
  exit 1
}
mkdir -p "$stage/licenses/wintun" "$stage/licenses/microsoft"

# Wintun, as pinned, unmodified (.claude/rules/dependencies.md).
mapfile -t pin < "$root/native/windows/wintun.pin"
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
cp "$work/wintun/bin/amd64/wintun.dll" "$stage/bin/"
cp "$work/wintun/LICENSE.txt" "$stage/licenses/wintun/LICENSE.txt"

# Microsoft's Visual C++ runtime, as pinned, and its licence terms.
"$root/packaging/windows/vcruntime.sh" "$stage/bin"
cp "$root"/packaging/windows/licenses/* "$stage/licenses/microsoft/"

# The setup program's licence page: what whoever installs UBC VPN accepts.
# Our own licence, then the third-party terms that need the user's
# agreement, Microsoft's in full (its licence for the Visual C++ runtime
# asks that end users agree to terms protecting it at least as much), and
# where the rest of the notices are installed.
version=$(cd "$root" && node -p "require('./app/package.json').version")
{
  cat <<EOF
UBC VPN $version

To install UBC VPN you must accept these terms: UBC VPN's own licence, and
the licence terms of the third-party software installed with it, below.
A silent install (/S) shows no page; running one means accepting them.
UBC VPN is not made by or affiliated with the University of British
Columbia.

All of these, and the other notices, are installed in the
resources\\licenses folder of UBC VPN's install folder.


1. UBC VPN

UBC VPN is free software, licensed under the MIT licence or the Apache
License 2.0, at your option. The full texts follow.

EOF
  cat "$root/LICENSE-MIT"
  printf '\n\n'
  cat "$root/LICENSE-APACHE"
  cat <<'EOF'


2. Microsoft Visual C++ runtime (vcruntime140.dll)

EOF
  cat "$root/packaging/windows/licenses/microsoft-vc-runtime-NOTICE.txt"
  printf '\n\n'
  cat "$root/packaging/windows/licenses/microsoft-visual-studio-2026-community-license.txt"
  cat <<'EOF'


3. Wintun (wintun.dll)

EOF
  cat "$work/wintun/LICENSE.txt"
  cat <<'EOF'


4. Other third-party software

- libopenconnect and the libraries it uses: under the GNU Lesser General
  Public License and other licences, each in resources\licenses\native.
  Their source is published as resources\licenses\SOURCES.txt says.
- Electron and Chromium: LICENSE.electron.txt and LICENSES.chromium.html
  in the install folder.
- The fonts Geist Mono and Instrument Sans: SIL Open Font License 1.1, in
  resources\licenses\fonts.
EOF
} > "$stage/license.txt"

echo "Added to $stage:"
(cd "$stage" && ls bin/wintun.dll bin/vcruntime140.dll license.txt licenses/wintun licenses/microsoft)
