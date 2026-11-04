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
        minos=$(otool -l "$folder/$name" | awk '/LC_BUILD_VERSION/ { found = 1 } found && $1 == "minos" { print $2; exit }')
        [ "$minos" = 14.0 ] || fail "$folder/$name declares macOS $minos, not 14.0"
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

# A system's own /usr/local and /usr/local/bin. The runner's may not be, and the
# link is made only in folders only root can change. Section 14 tries others.
ls -ldn /usr/local /usr/local/bin || true
sudo chown root:wheel /usr/local /usr/local/bin
sudo chmod 755 /usr/local /usr/local/bin

# --- 0. The package's minimum macOS stops an install ------------------------

# It is what keeps UBC VPN off a macOS older than 14: dyld does not refuse a
# library that declares a newer minimum. No runner is that old, so this is the
# same package with the same element asking for a macOS newer than this one:
# `installer` must refuse it, with nothing left behind.
newer=$(mktemp -d "$work/newer-XXXXXX")
rmdir "$newer"
pkgutil --expand "$pkg" "$newer"
grep -q 'os-version min="14.0"' "$newer/Distribution" || fail "the package does not ask for macOS 14.0"
sed 's/os-version min="14.0"/os-version min="99.0"/' "$newer/Distribution" > "$work/Distribution"
cp "$work/Distribution" "$newer/Distribution"
pkgutil --flatten "$newer" "$work/too-new.pkg"
sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/sbin/installer -pkg "$work/too-new.pkg" -target / > "$work/too-new.txt" 2>&1 || true
cat "$work/too-new.txt"
if grep -q 'The install was successful' "$work/too-new.txt"; then
    fail "a package asking for a newer macOS installed"
fi
# For that reason, not because flattening it again broke it.
grep -qF 'macOS version 99 or later is required' "$work/too-new.txt" || fail "it was refused for another reason"
[ ! -e "$APP" ] && [ ! -e "$FOLDER" ] && [ ! -e "$DATA" ] && [ ! -e "$PLIST" ] || fail "the refused package left something behind"
if pkgutil --pkgs | grep -F "$LABEL"; then fail "the refused package left a record"; fi
rm -rf "$newer" "$work/too-new.pkg" "$work/Distribution"
ran "minimum stops an install"

# --- 1. Install -------------------------------------------------------------

mkdir -p "$SETTINGS"
touch "$SETTINGS/marker"
# As it arrives from a browser, which marks it as downloaded. `installer` run
# with sudo does not ask about that; the Installer app does (for the owner to
# try). What Gatekeeper makes of the unsigned package, for the record.
xattr -w com.apple.quarantine "0081;00000000;Safari;" "$pkg"
spctl --assess --type install --verbose "$pkg" 2>&1 || true
install_pkg
pkgutil --pkg-info "$LABEL"
# Nothing it installs carries the mark, or launchd and the app would meet it.
marked=$(sudo xattr -r -l "$FOLDER" "$APP" 2> /dev/null | grep -F com.apple.quarantine || true)
[ -z "$marked" ] || fail "the mark reached what was installed: $marked"
ran "install"

# --- 1b. Only root can change what the script ran from ------------------------

# What the design rests on, on a real run: the script's own record of the folder
# macOS unpacked it to, and everything in it.
sudo grep -F 'ubc-vpn postinstall: scripts folder: ' /var/log/install.log |
    sed 's/.*scripts folder: //' > "$work/scripts-folder.txt"
cat "$work/scripts-folder.txt"
[ "$(wc -l < "$work/scripts-folder.txt")" -ge 10 ] || fail "the log does not hold the script's record"
awk '$3 != 0 || substr($1, 6, 1) == "w" || substr($1, 9, 1) == "w" { print; bad = 1 } END { exit bad }' \
    "$work/scripts-folder.txt" || fail "something the script ran from can be changed by others"
grep -qF "Scripts/$LABEL" "$work/scripts-folder.txt" || fail "that is not macOS's folder for the package's scripts"
ran "only root can change the scripts"

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

# --- 10b. A new service that cannot start: the old one comes back ---------------

# The package's scripts, with a library cut short, so the folder check and the
# install's own checks pass and the service fails as it starts.
broken=$(mktemp -d "$work/broken-XXXXXX")
rmdir "$broken"
pkgutil --expand-full "$pkg" "$broken"
bad_scripts="$broken/$LABEL.pkg/Scripts"
: > "$bad_scripts/service/libopenconnect.5.dylib"
# The update brings another policy, which must not stay with the old service.
sed 's/"gateway": *"[^"]*"/"gateway":"other.example.test"/' "$stage/pkg-scripts/policy.json" > "$bad_scripts/policy.json"
! cmp -s "$bad_scripts/policy.json" "$stage/pkg-scripts/policy.json" || fail "the new policy is the same"
running_postinstall() {
    sudo /usr/bin/env -i "$bad_scripts/postinstall" "$pkg" /Applications /
}
before=$(job_setting pid)
if running_postinstall; then fail "a service that cannot start was installed"; fi
service_is_right
[ "$(job_setting pid)" != "$before" ] || fail "the old service was not started again"
files_are_right
cmp "$DATA/policy.json" "$stage/pkg-scripts/policy.json"
[ "$(sha "$STATE")" = "$state" ] || fail "the failed update changed state.json"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
[ ! -e "$FOLDER.old" ] && [ ! -e "$FOLDER.next" ] && [ ! -e "$FOLDER.policy" ] || fail "the failed update left something behind"
ran "failed update, service cannot start"

# --- 10c. The job cannot be written: the old job comes back ----------------------

# The service has been stopped by then, and the job on disk cannot be replaced.
pkgutil --expand-full "$pkg" "$work/good-expanded"
sudo chflags uchg "$PLIST"
before=$(job_setting pid)
if sudo /usr/bin/env -i "$work/good-expanded/$LABEL.pkg/Scripts/postinstall" "$pkg" /Applications /; then
    sudo chflags nouchg "$PLIST"
    fail "an install that could not write its job passed"
fi
sudo chflags nouchg "$PLIST"
service_is_right
[ "$(job_setting pid)" != "$before" ] || fail "the service was never stopped: this tested nothing"
[ "$(sha "$STATE")" = "$state" ] || fail "the failed update changed state.json"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
[ ! -e "$FOLDER.old" ] && [ ! -e "$FOLDER.next" ] || fail "the failed update left a folder behind"
rm -rf "$broken" "$work/good-expanded"
ran "failed update, job cannot be written"

# --- 10d. The job on disk but not loaded, as a failed `launchctl bootstrap` leaves it ---

# launchctl is at a path only macOS can change, so a real install cannot be made
# to fail at this step. This is the state it leaves, and what the script does
# from it: an update's install loads the job again, and a first install's
# `uninstall --keep-data` removes it.
sudo launchctl bootout "$JOB"
gone_now() { [ -z "$(print_job)" ]; }
for _ in $(seq 225); do
    if gone_now; then break; fi
    sleep 0.2
done
gone_now || fail "the job did not go"
[ -e "$PLIST" ] || fail "bootout took the file"
sudo /usr/bin/env -i "$SERVICE" install --policy "$stage/pkg-scripts/policy.json"
service_is_right
[ "$(sha "$STATE")" = "$state" ] || fail "the owner was lost"
sudo launchctl bootout "$JOB"
for _ in $(seq 225); do
    if gone_now; then break; fi
    sleep 0.2
done
sudo /usr/bin/env -i "$SERVICE" uninstall --keep-data
[ ! -e "$PLIST" ] || fail "the job is left on disk"
install_pkg
[ "$(sha "$STATE")" = "$state" ] || fail "the owner was lost"
ran "job on disk not loaded"

# --- 10e. Folders others could change: nothing is touched, and nothing runs -------

# The scripts as a real run has them, from section 9.
postinstall_again="$inner/postinstall"
nothing_done() { # <what it is about>: the script and the removal both refuse
    local about=$1 pid listing lines
    pid=$(job_setting pid)
    listing=$(sudo ls -lnT "$HELPERS_REAL" 2>&1 || true)
    lines=$(sudo wc -l < "$DATA/service.log")
    if sudo /usr/bin/env -i "$postinstall_again" "$pkg" /Applications / 2> "$work/refused.txt"; then
        fail "$about: the install went ahead"
    fi
    grep -qF "only root must be able to change" "$work/refused.txt" || { cat "$work/refused.txt"; fail "$about: refused for another reason"; }
    if sudo /usr/bin/env -i "$UNINSTALL" 2> "$work/refused.txt"; then
        fail "$about: the removal went ahead"
    fi
    grep -qiF "only root must be able to change" "$work/refused.txt" || { cat "$work/refused.txt"; fail "$about: the removal refused for another reason"; }
    [ "$(job_setting pid)" = "$pid" ] || fail "$about: the service was touched"
    [ "$(sudo wc -l < "$DATA/service.log")" = "$lines" ] || fail "$about: the service logged something"
    [ "$(sudo ls -lnT "$HELPERS_REAL" 2>&1 || true)" = "$listing" ] || fail "$about: the folder changed"
}
HELPERS=/Library/PrivilegedHelperTools
HELPERS_REAL=$HELPERS
UNINSTALL=$FOLDER/uninstall.sh

sudo chmod g+w "$HELPERS"
nothing_done "$HELPERS open to its group"
sudo chmod g-w "$HELPERS"

sudo chown 501 "$HELPERS"
nothing_done "$HELPERS the user's"
sudo chown 0 "$HELPERS"

sudo chmod +a "everyone allow delete_child" "$HELPERS"
nothing_done "an access list on $HELPERS"
sudo chmod -N "$HELPERS"

sudo chmod g+w /Library
nothing_done "/Library open to its group"
sudo chmod g-w /Library

# A link in its place, to the real folder.
sudo mv "$HELPERS" "$HELPERS.aside"
sudo ln -s "$HELPERS.aside" "$HELPERS"
HELPERS_REAL=$HELPERS.aside
nothing_done "$HELPERS a link"
sudo rm -f "$HELPERS"
sudo mv "$HELPERS.aside" "$HELPERS"
HELPERS_REAL=$HELPERS
service_is_right
ran "helpers folder others could change"

# --- 10f. The script's other refusals, and its environment ------------------------

before=$(job_setting pid)
if sudo /usr/bin/env -i "$postinstall_again" "$pkg" /Applications /Volumes/Other 2> "$work/refused.txt"; then
    fail "the install went ahead on another disk"
fi
grep -qF "only on the startup disk" "$work/refused.txt" || fail "it was refused for another reason"
[ "$(job_setting pid)" = "$before" ] || fail "the refused install touched the service"
ran "another disk refused"

# Tools of someone else's first on PATH, and files and functions a shell could
# take from its environment. None of it may run.
evil=$(mktemp -d "$work/evil-XXXXXX")
chmod 755 "$evil"
cat > "$evil/rc" <<EOF
/usr/bin/touch "$work/evil-ran"
EOF
for name in mv rm install ls stat find sed cp ln env; do
    cat > "$evil/$name" <<EOF
#!/bin/sh
/usr/bin/touch "$work/evil-ran"
exit 0
EOF
    chmod 755 "$evil/$name"
done
sudo /usr/bin/env PATH="$evil:/usr/bin:/bin" BASH_ENV="$evil/rc" ENV="$evil/rc" CDPATH="$evil" \
    'BASH_FUNC_stat%%=() { /usr/bin/touch "'"$work"'/evil-ran"; }' \
    DYLD_INSERT_LIBRARIES="$evil/rc" "$postinstall_again" "$pkg" /Applications /
[ ! -e "$work/evil-ran" ] || fail "the install ran something from its environment"
service_is_right
files_are_right
[ "$(sha "$STATE")" = "$state" ] || fail "the hostile environment changed state.json"
ran "hostile environment"

# --- 10g. A run cut short between its moves ----------------------------------------

# The current folder moved aside and the new one not yet in place.
sudo mv "$FOLDER" "$FOLDER.old"
sudo /usr/bin/env -i "$postinstall_again" "$pkg" /Applications /
service_is_right
files_are_right
[ ! -e "$FOLDER.old" ] || fail "the old folder is left"
[ "$(sha "$STATE")" = "$state" ] || fail "the run cut short changed state.json"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "run cut short"

# --- 11. Removing it leaves nothing --------------------------------------------

# With what a run cut short leaves, which the removal takes too.
sudo mkdir "$FOLDER.old" "$FOLDER.next"
sudo touch "$FOLDER.policy"
sudo /usr/bin/env -i "$FOLDER/uninstall.sh"
for path in "$APP" "$FOLDER" "$FOLDER.old" "$FOLDER.next" "$FOLDER.policy" "$DATA" "$PLIST" "$LINK"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "$path is left"
done
status=0
sudo launchctl print "$JOB" > /dev/null 2>&1 || status=$?
[ "$status" = 113 ] || fail "launchd still knows the job ($status)"
if pgrep -x ubc-vpn-service; then fail "the service still runs"; fi
if pkgutil --pkgs | grep -F "$LABEL"; then fail "macOS still has a record of the package"; fi
[ -f "$SETTINGS/marker" ] || fail "the user's settings were removed"
ran "removal"

# --- 12. A first install whose service cannot start leaves no job ----------------

fresh_broken=$(mktemp -d "$work/fresh-XXXXXX")
rmdir "$fresh_broken"
pkgutil --expand-full "$pkg" "$fresh_broken"
: > "$fresh_broken/$LABEL.pkg/Scripts/service/libopenconnect.5.dylib"
if sudo /usr/bin/env -i "$fresh_broken/$LABEL.pkg/Scripts/postinstall" "$pkg" /Applications /; then
    fail "a service that cannot start was installed"
fi
[ ! -e "$PLIST" ] || fail "the job is left, starting a service that cannot start"
[ -z "$(print_job)" ] || fail "launchd still knows the job"
[ ! -e "$FOLDER" ] && [ ! -e "$FOLDER.next" ] || fail "the service's folder is left"
if pgrep -x ubc-vpn-service; then fail "the service still runs"; fi
rm -rf "$fresh_broken"
ran "failed first install"

# --- 13. It installs over what that left, as a first install -----------------------

# The data folder is still there. It holds the policy and nothing that names an
# owner, so this is a first install.
sudo test -d "$DATA" || fail "this tested nothing: the data folder is gone"
install_pkg
service_is_right
files_are_right
sudo test ! -e "$STATE" || fail "the old state came back"
[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
sudo /usr/bin/env -i "$FOLDER/uninstall.sh"
ran "install again"

# --- 14. Nothing but our link is changed in /usr/local ---------------------------

# Run with each of the things that could be there. Every time: the service is
# installed, nothing there is changed, no link is made, the reason is given
# with the client's full path, and the removal leaves it all as it was.
good=$(mktemp -d "$work/good-XXXXXX")
rmdir "$good"
pkgutil --expand-full "$pkg" "$good"
postinstall="$good/$LABEL.pkg/Scripts/postinstall"
place=$work/place
mkdir "$place"
sudo chown 501:80 "$place"
sudo chmod 700 "$place"
sudo touch "$place/marker"
sudo chown 501:80 "$place/marker"
describe() { sudo stat -f '%N %Su:%Sg %Lp %T%Y' "$@"; }
installed_without_link() { # <what it is about> <paths to compare, as they were>
    local about=$1
    shift
    local before after
    before=$(describe "$@")
    sudo /usr/bin/env -i "$postinstall" "$pkg" /Applications / > "$work/place.txt" 2>&1 || {
        cat "$work/place.txt"
        fail "$about: the install failed"
    }
    cat "$work/place.txt"
    service_is_right
    grep -qF "the ubc-vpn command is not linked" "$work/place.txt" || fail "$about: nothing said so"
    grep -qF "\"$BIN/ubc-vpn\"" "$work/place.txt" || fail "$about: the full path was not given, quoted"
    grep -qF "not with sudo" "$work/place.txt" || fail "$about: it did not say not to use sudo"
    after=$(describe "$@")
    [ "$after" = "$before" ] || fail "$about: it changed: $after"
    sudo /usr/bin/env -i "$FOLDER/uninstall.sh"
    after=$(describe "$@")
    [ "$after" = "$before" ] || fail "$about: the removal changed it: $after"
}
owned_by_root=$(stat -f '%Su:%Sg %Lp' /usr/local/bin)

# A file of someone else's, and a link of someone else's, at the link's place.
echo "someone else's" | sudo tee "$LINK" > /dev/null
installed_without_link "a file there" "$LINK"
[ "$(cat "$LINK")" = "someone else's" ] || fail "the install replaced a file at $LINK"
sudo rm -f "$LINK"
sudo ln -s /bin/ls "$LINK"
installed_without_link "a link there" "$LINK"
[ "$(readlink "$LINK")" = /bin/ls ] || fail "the install replaced a link at $LINK"
sudo rm -f "$LINK"

# Folders as Homebrew leaves them on an Intel Mac: the user's, in the admin group.
sudo chown 501:80 /usr/local/bin
sudo chmod 775 /usr/local/bin
installed_without_link "/usr/local/bin the user's" /usr/local/bin
[ ! -e "$LINK" ] || fail "a link was made in a folder the user can change"
# Our own link, in such a folder: it is not ours to change or remove there.
sudo -u "#501" ln -s "$BIN/ubc-vpn" "$LINK"
installed_without_link "our link in the user's folder" "$LINK" /usr/local/bin
[ "$(readlink "$LINK")" = "$BIN/ubc-vpn" ] || fail "the removal took a link in a folder the user can change"
sudo rm -f "$LINK"
sudo chown root:wheel /usr/local/bin
sudo chmod 755 /usr/local/bin

sudo chown 501:80 /usr/local
sudo chmod 775 /usr/local
installed_without_link "/usr/local the user's" /usr/local /usr/local/bin
[ ! -e "$LINK" ] || fail "a link was made under a folder the user can change"
sudo chown root:wheel /usr/local
sudo chmod 755 /usr/local

# An access list that lets someone else write.
sudo chmod +a "everyone allow add_file" /usr/local/bin
installed_without_link "an access list on /usr/local/bin" /usr/local/bin
[ ! -e "$LINK" ] || fail "a link was made in a folder others can change"
sudo chmod -N /usr/local/bin

# The link cannot be made: the service is up by then, so the install still stands.
sudo chflags uchg /usr/local/bin
installed_without_link "the link cannot be made" /usr/local/bin
[ ! -e "$LINK" ] || fail "a link was made in a folder marked unchangeable"
sudo chflags nouchg /usr/local/bin

# A link in the folder's place, to a folder of the user's.
sudo mv /usr/local/bin "$work/bin-aside"
sudo ln -s "$place" /usr/local/bin
installed_without_link "/usr/local/bin a link" /usr/local/bin "$place" "$place/marker"
[ ! -e "$place/ubc-vpn" ] && [ ! -L "$place/ubc-vpn" ] || fail "a link was made through a link"
[ "$(sudo ls -A "$place")" = marker ] || fail "the folder behind the link changed"
sudo rm -f /usr/local/bin

# No folder at all: it is not made.
installed_without_link "no /usr/local/bin" /usr/local
[ ! -e /usr/local/bin ] || fail "the install made /usr/local/bin"
sudo mv "$work/bin-aside" /usr/local/bin

[ "$(stat -f '%Su:%Sg %Lp' /usr/local/bin)" = "$owned_by_root" ] || fail "the test left /usr/local/bin as $(stat -f '%Su:%Sg %Lp' /usr/local/bin)"
sudo rm -rf "$place"
ran "nothing else changed in /usr/local"

# --- 15. Nothing in the app runs as root, or goes into the service ---------------

# The admin group can write to /Applications. So with every file a package
# script could use swapped there, as it stands when the script runs: nothing of
# it runs, and the service, its libraries and the policy are the package's.
install_pkg
sudo rm -rf "$work/ran-from-app"
planted=$(mktemp "$work/planted-XXXXXX")
cat > "$planted" <<EOF
#!/bin/sh
/usr/bin/touch "$work/ran-from-app"
EOF
for name in ubc-vpn ubc-vpn-service; do
    sudo cp "$planted" "$BIN/$name"
    sudo chmod 755 "$BIN/$name"
done
sudo cp "$planted" "$APP/Contents/MacOS/UBC VPN"
sudo chmod 755 "$APP/Contents/MacOS/UBC VPN"
for name in $LIBRARIES; do
    echo planted | sudo tee "$BIN/$name" > /dev/null
done
echo '{"gateway":"planted.example.test","pins":[]}' | sudo tee "$APP/Contents/Resources/policy.json" > /dev/null
sudo /usr/bin/env -i "$postinstall" "$pkg" /Applications /
[ ! -e "$work/ran-from-app" ] || fail "the install ran something from the app"
service_is_right
for name in $(ls -A "$FOLDER"); do
    cmp "$stage/pkg-scripts/service/$name" "$FOLDER/$name"
done
cmp "$DATA/policy.json" "$stage/pkg-scripts/policy.json"
sudo /usr/bin/env -i "$FOLDER/uninstall.sh"
[ ! -e "$work/ran-from-app" ] || fail "the removal ran something from the app"
[ ! -e "$FOLDER" ] && [ ! -e "$APP" ] || fail "the removal left something"
rm -rf "$good"
ran "nothing runs from the app"
