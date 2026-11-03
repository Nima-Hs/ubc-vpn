#!/usr/bin/env bash
# Installs the .pkg on this machine with `installer`, as the Installer app does
# once it has its admin prompt, and checks the whole life of it: what landed
# where, who can change it, that the service answers a standard user, an update
# over itself with the service running, the scripts run twice, an update that
# fails, and that removing it leaves nothing. Says "RAN: <name>" after each
# check that passed; the workflow requires every name in
# .github/ran/installer-macos/macos.
#
# Only for a throwaway CI runner: it installs a root service and changes
# /Applications and /Library. The workflow sets UBC_VPN_TEST_THROWAWAY_MACHINE
# on GitHub's own runners only. Never run it on a machine that is kept.
#
# Usage: installer.sh <pkg> <stage> <folder>
#   <stage> is app/stage from the job that built the package. <folder> is made
#   for the test's own files. Needs passwordless sudo. Runs on macOS's bash 3.2.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }
ran() { echo "RAN: $1"; }

[ $# -eq 3 ] || fail "usage: installer.sh <pkg> <stage> <folder>"
[ "${UBC_VPN_TEST_THROWAWAY_MACHINE:-}" = 1 ] || fail "only for a throwaway CI runner"
[ "$(uname)" = Darwin ] || fail "this is not macOS"
pkg=$1
stage=$(cd "$2" && pwd)
mkdir "$3"
work=$(cd "$3" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

LABEL=io.github.nima-hs.ubc-vpn
JOB=system/$LABEL
FOLDER=/Library/PrivilegedHelperTools/$LABEL
SERVICE=$FOLDER/ubc-vpn-service
PLIST=/Library/LaunchDaemons/$LABEL.plist
DATA="/Library/Application Support/UBC VPN"
STATE=$DATA/state.json
APP="/Applications/UBC VPN.app"
BIN="$APP/Contents/Resources/bin"
LINK=/usr/local/bin/ubc-vpn
LIBRARIES="libgmp.10.dylib libgnutls.30.dylib libhogweed.7.dylib libnettle.9.dylib libopenconnect.5.dylib"
# The account's settings, which no removal may touch.
SETTINGS="$HOME/Library/Application Support/UBC VPN"

[ ! -e "$APP" ] && [ ! -e "$FOLDER" ] && [ ! -e "$DATA" ] && [ ! -e "$PLIST" ] || fail "UBC VPN is installed here"

# The owner's and anyone else's view, as a person types it: nothing of this
# script's environment, through the command's link.
client() {
    env -i HOME="$HOME" PATH=/usr/bin:/bin "$LINK" "$@"
}
stranger() {
    sudo -u nobody env -i HOME=/nonexistent PATH=/usr/bin:/bin "$LINK" "$@"
}
install_pkg() {
    sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/sbin/installer -pkg "$pkg" -target /
}
owner_and_mode() {
    sudo stat -f '%u:%g %Lp' "$1"
}
print_job() {
    sudo launchctl print "$JOB" 2> /dev/null || true
}
job_setting() {
    print_job | sed -n "s/^	$1 = //p" | head -n 1
}
sha() {
    sudo shasum -a 256 "$1"
}
service_is_right() {
    [ "$(job_setting state)" = running ] || fail "the job is $(job_setting state)"
    [ "$(job_setting program)" = "$SERVICE" ] || fail "launchd runs $(job_setting program)"
    [ "$(ps -o user= -p "$(job_setting pid)" | tr -d ' ')" = root ] || fail "the service does not run as root"
    [ "$(ps -o comm= -p "$(job_setting pid)")" = "$SERVICE" ] || fail "launchd runs another program"
}
# Each of these files is a real file, and has the ad-hoc signature it was built
# with: Apple silicon runs nothing unsigned, and nothing here signs again.
signed_as_built() { # <folder> <name>...
    local folder=$1 name signature
    shift
    for name in "$@"; do
        [ -f "$folder/$name" ] && [ ! -L "$folder/$name" ] || fail "$folder/$name is not a file"
        codesign --verify --strict "$folder/$name"
        signature=$(codesign -dv "$folder/$name" 2>&1)
        grep -qx 'Signature=adhoc' <<<"$signature" || fail "$folder/$name is not signed ad hoc"
        if otool -l "$folder/$name" | grep -q LC_RPATH; then
            fail "$folder/$name has a search path: the loader would search a folder no one checked"
        fi
    done
}
files_are_right() {
    # The service's folder is the stage's, byte for byte, and nothing else.
    [ "$(ls -A "$FOLDER" | sort)" = "$(ls -A "$stage/pkg-scripts/service" | sort)" ] || fail "$FOLDER holds other files than the stage"
    for name in $(ls -A "$FOLDER"); do
        cmp "$stage/pkg-scripts/service/$name" "$FOLDER/$name"
    done
    # The app's programs too, and every file of the package's.
    [ "$(ls -A "$BIN" | sort)" = "$(ls -A "$stage/bin" | sort)" ] || fail "$BIN holds other files than the stage"
    for name in $(ls -A "$BIN"); do
        cmp "$stage/bin/$name" "$BIN/$name"
    done
    (cd "$stage/licenses" && find . -type f -print0) | while IFS= read -r -d '' file; do
        cmp "$stage/licenses/$file" "$APP/Contents/Resources/licenses/$file"
    done
    expanded=$(mktemp -d "$work/expanded-XXXXXX")
    rmdir "$expanded"
    pkgutil --expand-full "$pkg" "$expanded"
    payload="$expanded/$LABEL.pkg/Payload/UBC VPN.app"
    (cd "$payload" && find . -type f -print0) | while IFS= read -r -d '' file; do
        cmp "$payload/$file" "$APP/$file"
    done
    extra=$(comm -13 <(cd "$payload" && find . | sort) <(cd "$APP" && find . | sort))
    [ -z "$extra" ] || fail "in the app but not in the package: $extra"
    rm -rf "$expanded"
    # shellcheck disable=SC2086 # The list is words.
    signed_as_built "$FOLDER" ubc-vpn-service $LIBRARIES
    # shellcheck disable=SC2086
    signed_as_built "$BIN" ubc-vpn $LIBRARIES
    [ "$(readlink "$LINK")" = "$BIN/ubc-vpn" ] || fail "$LINK does not point to the client"
}
who_can_change() {
    # The service's folder, every folder above it and every file in it: real,
    # root's, and writable by root alone, with no access list that allows
    # anything. The service checks the same when it starts.
    local path=$FOLDER mode list
    while :; do
        [ -d "$path" ] && [ ! -L "$path" ] || fail "$path is not a real folder"
        [ "$(stat -f %u "$path")" = 0 ] || fail "$path is not root's"
        mode=$(stat -f %Lp "$path")
        [ $((0$mode & 022)) = 0 ] || fail "$path can be changed by others ($mode)"
        list=$(ls -lde "$path")
        if grep -E '^ *[0-9]+: .* allow ' <<<"$list"; then fail "$path has an access list that allows"; fi
        [ "$path" = / ] && break
        path=$(dirname "$path")
    done
    open=$(sudo find "$FOLDER" \( ! -uid 0 -o -perm +022 \) -print)
    [ -z "$open" ] || fail "others can change: $open"
    # The whole app: root's, and nothing others may change. The folder it is in
    # is another matter: the admin group can write to /Applications, which is
    # why the service does not run from there.
    open=$(sudo find "$APP" \( ! -uid 0 -o \( -perm +022 ! -type l \) \) -print)
    [ -z "$open" ] || fail "others can change: $open"
    [ "$(owner_and_mode "$LINK" | cut -d' ' -f1)" = 0:0 ] || fail "$LINK is $(owner_and_mode "$LINK")"
}

# --- 1. Install -------------------------------------------------------------

mkdir -p "$SETTINGS"
touch "$SETTINGS/marker"
install_pkg
pkgutil --pkg-info "$LABEL"
ran "install"

# --- 2. Everything landed as packaged and staged ----------------------------

files_are_right
ran "files as packaged"

# --- 3. Only root can change the service --------------------------------------

who_can_change
ran "who can change"

# --- 4. The installed app is as it should be --------------------------------

(cd "$repo/app" && node scripts/check-package.mjs mac "$APP")
ran "installed app"

# --- 5. The service runs, with the package's policy --------------------------

service_is_right
cmp "$DATA/policy.json" "$stage/pkg-scripts/policy.json"
[ "$(owner_and_mode "$DATA")" = "0:0 755" ] || fail "the data folder"
cmp "$PLIST" "$repo/packaging/macos/$LABEL.plist"
ran "service"

# --- 6. The app starts ------------------------------------------------------

# As a person starts it, from the install, as this standard account. It must
# load, with what it holds and what macOS gives it, and stay up. The runner's
# session can show a window, and nobody is there to see it.
"$APP/Contents/MacOS/UBC VPN" > "$work/app.log" 2>&1 &
app=$!
sleep 15
if ! kill -0 "$app" 2> /dev/null; then
    cat "$work/app.log"
    fail "the app did not stay up"
fi
kill "$app"
wait "$app" 2> /dev/null || true
if grep -E 'dyld|Library not loaded|Code Signature Invalid' "$work/app.log"; then
    fail "the app could not load something"
fi
ran "app starts"

# --- 7. A standard user owns it, and through the command -----------------------

[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
sudo grep -q owner "$STATE" || fail "no owner in state.json"
status=0
stranger status > "$work/stranger.txt" 2>&1 || status=$?
cat "$work/stranger.txt"
[ "$status" = 5 ] || fail "another user was not refused as not the owner (status $status)"
ran "owner"

# --- 8. An update over itself keeps the service's state and owner ---------------

state=$(sha "$STATE")
before=$(job_setting pid)
install_pkg
[ "$(sha "$STATE")" = "$state" ] || fail "an update changed state.json"
[ "$(job_setting pid)" != "$before" ] || fail "an update did not start the service again"
service_is_right
files_are_right
who_can_change
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
status=0
stranger status > /dev/null 2>&1 || status=$?
[ "$status" = 5 ] || fail "another user was not refused after the update"
[ ! -e "$FOLDER.old" ] && [ ! -e "$FOLDER.next" ] || fail "the update left a folder behind"
ran "update over itself"

# --- 9. The script is safe to repeat ------------------------------------------

scripts=$(mktemp -d "$work/scripts-XXXXXX")
rmdir "$scripts"
pkgutil --expand-full "$pkg" "$scripts"
inner="$scripts/$LABEL.pkg/Scripts"
for _ in 1 2; do
    sudo /usr/bin/env -i "$inner/postinstall" "$pkg" /Applications /
done
[ "$(sha "$STATE")" = "$state" ] || fail "running the script again changed state.json"
service_is_right
files_are_right
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "scripts twice"

# --- 10. An update that fails leaves what was there -----------------------------

# A data folder others can change stops the install. The service must be the
# old one, still running, from a folder with the same files.
before=$(job_setting pid)
sudo chmod 775 "$DATA"
if install_pkg; then fail "an update took a data folder others can change"; fi
[ "$(job_setting pid)" = "$before" ] || fail "the failed update stopped the service"
service_is_right
[ -e "$SERVICE" ] || fail "the failed update took the service's folder"
[ ! -e "$FOLDER.old" ] && [ ! -e "$FOLDER.next" ] || fail "the failed update left a folder behind"
[ "$(owner_and_mode "$DATA")" = "0:0 775" ] || fail "the failed update fixed the data folder"
sudo chmod 755 "$DATA"
install_pkg
[ "$(sha "$STATE")" = "$state" ] || fail "the owner was lost"
ran "failed update"

# --- 11. Removing it leaves nothing --------------------------------------------

sudo /usr/bin/env -i "$FOLDER/uninstall.sh"
for path in "$APP" "$FOLDER" "$FOLDER.old" "$FOLDER.next" "$DATA" "$PLIST" "$LINK"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "$path is left"
done
status=0
sudo launchctl print "$JOB" > /dev/null 2>&1 || status=$?
[ "$status" = 113 ] || fail "launchd still knows the job ($status)"
if pgrep -x ubc-vpn-service; then fail "the service still runs"; fi
if pkgutil --pkgs | grep -F "$LABEL"; then fail "macOS still has a record of the package"; fi
[ -f "$SETTINGS/marker" ] || fail "the user's settings were removed"
ran "removal"

# --- 12. It installs again, as a first install ----------------------------------

install_pkg
service_is_right
sudo test ! -e "$STATE" || fail "the old state came back"
[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
sudo /usr/bin/env -i "$FOLDER/uninstall.sh"
ran "install again"
