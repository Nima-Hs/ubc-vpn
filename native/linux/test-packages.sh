#!/usr/bin/env bash
# Installs packages that CI needs, at pinned versions, from a dated snapshot
# of the Ubuntu archive: ocserv for the native Linux workflow's probe and the
# engine's ocserv tests (crates/engine/tests/ocserv/start.sh), and the D-Bus
# headers and pkg-config that building the command-line client on Linux
# needs (its keyring links the system's libdbus-1 at run time).
#
# Only for a throwaway CI runner on Ubuntu 22.04 or 24.04: it fetches
# package lists as root and installs packages. Never run it on a machine
# that is kept.
#
# Usage: test-packages.sh <folder> <package>...
#   <folder> is a scratch folder for the snapshot's source list. Each
#   package must be one pinned below for the runner's Ubuntu release.
set -euo pipefail

# Everything comes from this dated snapshot, the one native/linux/build.sh
# uses, and each package at exactly the version pinned for the runner's
# release. libdbus-1-dev needs the system's libdbus-1-3 at its own version:
# if the runner's image has another, apt stops, and the snapshot and these
# pins are moved together.
APT_SNAPSHOT=20261011T000000Z
declare -A PINNED_jammy=(
    [ocserv]=1.1.3-1
    [pkg-config]=0.29.2-1ubuntu3
    [libdbus-1-dev]=1.12.20-2ubuntu4.1
)
declare -A PINNED_noble=(
    [pkg-config]=1.8.1-2build1
    [libdbus-1-dev]=1.14.10-4ubuntu4.1
)

fail() { echo "error: $*" >&2; exit 1; }
[ $# -ge 2 ] || fail "usage: test-packages.sh <folder> <package>..."
dir=$(cd "$1" && pwd)
shift
codename=$(sed -n 's/^DISTRIB_CODENAME=//p' /etc/lsb-release)
case "$codename" in
    jammy | noble) ;;
    *) fail "this is not Ubuntu 22.04 or 24.04" ;;
esac
declare -n PINNED="PINNED_$codename"
wanted=()
for package in "$@"; do
    [ -n "${PINNED[$package]:-}" ] || fail "$package is not a pinned test package on $codename"
    wanted+=("$package=${PINNED[$package]}")
done

# Only the snapshot is asked: the machine's own sources are set aside for
# these commands, and apt must download nothing from anywhere else.
snapshot_url="https://snapshot.ubuntu.com/ubuntu/$APT_SNAPSHOT"
sources="$dir/snapshot.list"
cat > "$sources" <<EOF
deb $snapshot_url $codename main universe
deb $snapshot_url $codename-updates main universe
deb $snapshot_url $codename-security main universe
EOF
apt_opts=(-o "Dir::Etc::sourcelist=$sources" -o "Dir::Etc::sourceparts=-")
# The snapshot service fails now and then for a while: apt retries each
# download and gives up on a stalled one, an index it cannot fetch is an
# error rather than a warning, and each network step as a whole is tried up
# to three times. What may be installed, and from where, is checked the same
# on every try.
apt_opts+=(-o "Acquire::Retries=5" -o "Acquire::http::Timeout=30" -o "Acquire::https::Timeout=30"
    -o "APT::Update::Error-Mode=any")
retry() {
    local attempt
    for attempt in 1 2 3; do
        if "$@"; then
            return 0
        fi
        if [ "$attempt" -lt 3 ]; then
            echo "try $attempt of 3 failed; trying again in $((attempt * 20)) seconds" >&2
            sleep $((attempt * 20))
        fi
    done
    fail "the snapshot could not be reached after 3 tries: $*"
}

# Whether every package asked for is already installed at its pinned
# version, so that apt has nothing to download.
all_in_place() {
    local package
    for package in "$@"; do
        [ "$(dpkg-query -W -f '${Version}' "$package" 2>/dev/null)" = "${PINNED[$package]}" ] || return 1
    done
}

export DEBIAN_FRONTEND=noninteractive
# Fetches the package lists and sets `uris` to what apt would download. An
# empty list, with packages still to install, means the lists were not all
# fetched: that is tried again too.
list_downloads() {
    sudo apt-get "${apt_opts[@]}" update || return 1
    uris=$(sudo apt-get "${apt_opts[@]}" install -y --no-install-recommends --print-uris \
        "${wanted[@]}" | grep -o "^'[^']*'" | tr -d "'" || true)
    [ -n "$uris" ] || all_in_place "$@"
}
retry list_downloads "$@"
echo "Packages to download:"
echo "${uris:-(none)}"
stray=$(grep -v "^$snapshot_url/" <<<"$uris" || true)
[ -z "$stray" ] || fail "these packages are not from the snapshot: $stray"

# A package with a service would start it, with the package's own settings:
# ocserv's listens on every address at port 443. A policy-rc.d that refuses
# every start keeps any of them from ever running; it is removed once the
# packages are in.
[ ! -e /usr/sbin/policy-rc.d ] || fail "/usr/sbin/policy-rc.d is already there"
printf '#!/bin/sh\nexit 101\n' | sudo tee /usr/sbin/policy-rc.d > /dev/null
sudo chmod 755 /usr/sbin/policy-rc.d
retry sudo apt-get "${apt_opts[@]}" install -y --no-install-recommends "${wanted[@]}"
sudo rm /usr/sbin/policy-rc.d

for package in "$@"; do
    installed=$(dpkg-query -W -f '${Version}' "$package")
    [ "$installed" = "${PINNED[$package]}" ] ||
        fail "$package $installed is installed, not ${PINNED[$package]}"
    echo "$package $installed from $snapshot_url"
done
