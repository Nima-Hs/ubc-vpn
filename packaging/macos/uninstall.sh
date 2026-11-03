#!/bin/bash
# Removes UBC VPN from this Mac: a .pkg has no uninstall of its own. Run it in
# Terminal:
#
#   sudo /Library/PrivilegedHelperTools/io.github.nima-hs.ubc-vpn/uninstall.sh
#
# It stops the service, which removes its routes and DNS first, and removes the
# service and its folder, the policy and the state, the app, the `ubc-vpn`
# command and the record of the package. Each user's own settings stay in their
# ~/Library/Application Support/UBC VPN, as on the other systems.
set -euo pipefail

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

LABEL=io.github.nima-hs.ubc-vpn
FOLDER=/Library/PrivilegedHelperTools/$LABEL
LINK=/usr/local/bin/ubc-vpn
APP="/Applications/UBC VPN.app"
CLIENT="$APP/Contents/Resources/bin/ubc-vpn"

[ "$(id -u)" = 0 ] || { echo "Run this with sudo." >&2; exit 1; }

/usr/bin/env -i "$FOLDER/ubc-vpn-service" uninstall

if [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$CLIENT" ]; then
    rm -f "$LINK"
fi
rm -rf "$APP"
# Not an error when the record is gone already.
pkgutil --forget "$LABEL" > /dev/null 2>&1 || true
rm -rf "$FOLDER"
echo "UBC VPN has been removed."
