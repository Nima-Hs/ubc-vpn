#!/bin/bash -p
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
unset CDPATH

LABEL=io.github.nima-hs.ubc-vpn
FOLDER=/Library/PrivilegedHelperTools/$LABEL
HELPERS=/Library/PrivilegedHelperTools
LINK=/usr/local/bin/ubc-vpn
APP="/Applications/UBC VPN.app"
CLIENT="$APP/Contents/Resources/bin/ubc-vpn"

# Whether $1 is a real folder, root's, and changeable by root alone. Anything
# that can't be told is a no.
only_root_changes() {
    local mode list
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -f %u "$1")" = 0 ] || return 1
    mode=$(stat -f %Lp "$1")
    [ $((0$mode & 022)) = 0 ] || return 1
    list=$(ls -lde "$1") || return 1
    ! grep -qE '^ *[0-9]+: .* allow ' <<<"$list"
}

[ "$(id -u)" = 0 ] || { echo "Run this with sudo." >&2; exit 1; }
# This runs the service as root, and removes things, from these folders.
for folder in / /Library "$HELPERS"; do
    only_root_changes "$folder" || { echo "Only root must be able to change $folder." >&2; exit 1; }
done

/usr/bin/env -i "$FOLDER/ubc-vpn-service" uninstall

# Only our own link, and only in a folder that is what the install required:
# one that is real and root's alone. Anything else there is not ours to touch.
if only_root_changes /usr/local && only_root_changes /usr/local/bin &&
    [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$CLIENT" ]; then
    rm -f "$LINK"
fi
rm -rf "$APP"
# Not an error when the record is gone already.
pkgutil --forget "$LABEL" > /dev/null 2>&1 || true
# With what a run of the install that was cut short left.
rm -rf "$FOLDER" "$FOLDER.next" "$FOLDER.old" "$FOLDER.policy"
echo "UBC VPN has been removed."
