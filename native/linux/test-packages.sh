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
#   TEST_PACKAGES_CACHE, if set, is the folder that keeps the package lists
#   and packages between runs; otherwise they are kept in <folder>.
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
# these commands, apt must download nothing from anywhere else, and the
# snapshot's lists must be signed by the Ubuntu archive key.
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
[ -r "$keyring" ] || fail "$keyring is missing"
snapshot_url="https://snapshot.ubuntu.com/ubuntu/$APT_SNAPSHOT"
suites=("$codename" "$codename-updates" "$codename-security")
sources="$dir/snapshot.list"
for suite in "${suites[@]}"; do
    echo "deb [signed-by=$keyring] $snapshot_url $suite main universe"
done > "$sources"

# What apt fetches is kept in a folder of its own, which CI saves with
# actions/cache and restores in later runs (TEST_PACKAGES_CACHE): the
# snapshot's signed package lists and the packages they list. Then a run
# needs nothing from the snapshot, which is down now and then for hours.
# Nothing in the folder is trusted: on every run the lists' signatures are
# checked again, and every package against the signed lists, whether it was
# just downloaded or restored. Anything that does not match stops the
# script; it is never fetched again in its place.
cache=${TEST_PACKAGES_CACHE:-$dir/cache}
lists="$cache/lists"
debs="$cache/debs"
mkdir -p "$lists/partial" "$debs/partial"
work=$(mktemp -d "$dir/work.XXXXXX")
mkdir -p "$work/empty/partial"
apt_opts=(-o "Dir::Etc::sourcelist=$sources" -o "Dir::Etc::sourceparts=-"
    -o "Dir::State::lists=$lists/" -o "Dir::Cache::pkgcache=" -o "Dir::Cache::srcpkgcache="
    -o "Acquire::Languages=none" -o "Acquire::IndexTargets::deb::CNF::DefaultEnabled=false"
    -o "Acquire::GzipIndexes=false")
# When the snapshot must be asked, it may be failing for a while: apt
# retries each download and gives up on a stalled one, an index it cannot
# fetch is an error rather than a warning, and each network step as a whole
# is tried up to six times over about eight minutes. What may be installed,
# and from where, is checked the same on every try.
apt_opts+=(-o "Acquire::Retries=5" -o "Acquire::http::Timeout=30" -o "Acquire::https::Timeout=30"
    -o "APT::Update::Error-Mode=any")
TRIES=6
retry() {
    local attempt wait
    for attempt in $(seq "$TRIES"); do
        if "$@"; then
            return 0
        fi
        if [ "$attempt" -lt "$TRIES" ]; then
            wait=$((attempt < 5 ? attempt * 30 : 180))
            echo "try $attempt of $TRIES failed; trying again in $wait seconds" >&2
            sleep "$wait"
        fi
    done
    fail "the snapshot could not be reached after $TRIES tries: $*"
}

# Makes the folder the runner's own, so that it can be checked and saved.
own_cache() {
    sudo rm -f "$lists/lock" "$debs/lock"
    sudo chown -R "$(id -u):$(id -g)" "$cache"
}

# Whether every file in the lists is one the snapshot signed: each suite's
# InRelease has a good signature by the archive key and names that suite,
# and every other file has the size and SHA-256 that its suite's InRelease
# gives for its path. Only the signed part of an InRelease is read.
list_prefix=$(sed 's|^https://||; s|/|_|g' <<<"$snapshot_url")
verify_lists() {
    local suite release status file name path size hash matched
    for suite in "${suites[@]}"; do
        release="$lists/${list_prefix}_dists_${suite}_InRelease"
        [ -f "$release" ] || { echo "the lists have no InRelease for $suite" >&2; return 1; }
        rm -f "$work/$suite.Release"
        status=$(gpgv --status-fd 1 --keyring "$keyring" --output "$work/$suite.Release" "$release" 2>/dev/null || true)
        if ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" || grep -q '^\[GNUPG:\] BADSIG ' <<<"$status"; then
            echo "$release is not signed by the Ubuntu archive key" >&2
            return 1
        fi
        grep -qx "Suite: $suite" "$work/$suite.Release" || { echo "$release is not for $suite" >&2; return 1; }
    done
    while IFS= read -r -d '' file; do
        name=${file#"$lists/"}
        matched=
        for suite in "${suites[@]}"; do
            [[ $name == "${list_prefix}_dists_${suite}_"* ]] || continue
            path=${name#"${list_prefix}_dists_${suite}_"}
            if [ "$path" = InRelease ]; then
                matched=1
            else
                path=${path//_//}
                size=$(stat -c %s "$file")
                hash=$(sha256sum "$file" | cut -d ' ' -f 1)
                if awk -v h="$hash" -v s="$size" -v p="$path" '
                    /^[^ ]/ { section = $0 }
                    section == "SHA256:" && $1 == h && $2 == s && $3 == p { ok = 1 }
                    END { exit !ok }' "$work/$suite.Release"; then
                    matched=1
                fi
            fi
            break
        done
        [ -n "$matched" ] || { echo "$name in the lists is not one the snapshot signed" >&2; return 1; }
    done < <(find "$lists" -type f ! -path "$lists/partial/*" -print0)
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
# Fetches the snapshot's lists into an empty folder and checks them.
fetch_lists() {
    sudo find "$lists" -mindepth 1 -delete
    mkdir -p "$lists/partial"
    sudo apt-get "${apt_opts[@]}" update || return 1
    own_cache
    verify_lists
}
if [ -f "$cache/lists.ok" ]; then
    verify_lists || fail "the cached lists in $lists are not the snapshot's signed lists"
    echo "Package lists: already in $cache, signatures checked again; the snapshot was not asked"
else
    retry fetch_lists
    touch "$cache/lists.ok"
    echo "Package lists: fetched from $snapshot_url, signatures checked"
fi

# What apt would download, with each package's size and hash from the signed
# lists. Listed as if nothing were downloaded yet, so that every package is
# checked, cached or not. An empty list, with packages still to install,
# means something is wrong with the lists.
listing=$(sudo apt-get "${apt_opts[@]}" -o "Dir::Cache::archives=$work/empty/" install -y \
    --no-install-recommends --print-uris "${wanted[@]}" | grep "^'" || true)
uris=$(cut -d "'" -f 2 <<<"$listing")
[ -n "$uris" ] || all_in_place "$@" || fail "apt would download nothing, yet not every package is installed"
echo "Packages to download:"
echo "${listing:-(none)}"
stray=$(grep -v "^$snapshot_url/" <<<"$uris" || true)
[ -z "$stray" ] || fail "these packages are not from the snapshot: $stray"

if [ -n "$listing" ]; then
    missing=0
    while read -r _ name _ _; do
        [ -f "$debs/$name" ] || missing=1
    done <<<"$listing"
    if [ "$missing" = 1 ]; then
        retry sudo apt-get "${apt_opts[@]}" -o "Dir::Cache::archives=$debs/" install -y \
            --no-install-recommends --download-only "${wanted[@]}"
        own_cache
        echo "Packages: downloaded from $snapshot_url"
    else
        echo "Packages: already in $cache; the snapshot was not asked"
    fi
    while read -r _ name size hash; do
        case "$hash" in
            SHA512:*) sum=sha512sum ;;
            SHA256:*) sum=sha256sum ;;
            *) fail "the lists give no SHA-256 or SHA-512 for $name: $hash" ;;
        esac
        file="$debs/$name"
        [ -f "$file" ] || fail "$name was not downloaded"
        [ "$(stat -c %s "$file")" = "$size" ] && [ "$($sum "$file" | cut -d ' ' -f 1)" = "${hash#*:}" ] ||
            fail "$name is not the package the snapshot's signed lists give"
        echo "$name: size and ${hash%%:*} match the signed lists"
    done <<<"$listing"
fi

# A package with a service would start it, with the package's own settings:
# ocserv's listens on every address at port 443. A policy-rc.d that refuses
# every start keeps any of them from ever running; it is removed once the
# packages are in. Only the packages checked above are installed: apt may
# download nothing here.
[ ! -e /usr/sbin/policy-rc.d ] || fail "/usr/sbin/policy-rc.d is already there"
printf '#!/bin/sh\nexit 101\n' | sudo tee /usr/sbin/policy-rc.d > /dev/null
sudo chmod 755 /usr/sbin/policy-rc.d
sudo apt-get "${apt_opts[@]}" -o "Dir::Cache::archives=$debs/" install -y --no-install-recommends \
    --no-download "${wanted[@]}"
sudo rm /usr/sbin/policy-rc.d
own_cache
rm -rf "$work" "$lists/partial" "$debs/partial"

for package in "$@"; do
    installed=$(dpkg-query -W -f '${Version}' "$package")
    [ "$installed" = "${PINNED[$package]}" ] ||
        fail "$package $installed is installed, not ${PINNED[$package]}"
    echo "$package $installed from $snapshot_url"
done
