#!/usr/bin/env bash
# Checks the .deb and the .rpm as the installer workflow installs, updates
# and removes them (.github/workflows/installer-linux.yml). One command per
# step, on a runner, for the .deb:
#
#   installer.sh prepare                    closes /opt as a system's own is, adds a
#                                           standard user with an app profile
#   installer.sh install <deb>              installs what it depends on, then dpkg -i
#   installer.sh installed <deb>            every file is installed as packaged, and
#                                           nothing else is in /opt/UBC VPN
#   installer.sh as-staged <stage>          the programs, library, licences and policy
#                                           are the staged ones, byte for byte
#   installer.sh who-can-change             only root can change the service's folder,
#                                           the folders above it, or the app
#   installer.sh no-rpath                   the service, client and library have no
#                                           rpath or runpath
#   installer.sh service                    the unit runs the installed service with
#                                           the package's policy
#   installer.sh status-as-user             a standard user's `ubc-vpn status` answers,
#                                           and that user owns the service
#   installer.sh remember-files <file>      notes the package's files in <file>
#   installer.sh remember-state <file>      notes state.json's SHA-256 in <file>
#   installer.sh state-kept <file>          state.json is unchanged since then
#   installer.sh links                      /usr/bin/ubc-vpn and /usr/bin/ubc-vpn-app are
#                                           links to the client and the app
#   installer.sh no-conffiles               dpkg keeps no file of the package as its own
#   installer.sh scripts-twice              the install and removal scripts run twice
#                                           on an update leave the service running
#   installer.sh remove                     apt-get remove
#   installer.sh removed <file>             nothing is left but the user's data and
#                                           dpkg's record, <file> from remember-files
#   installer.sh purge                      apt-get purge
#   installer.sh purged <file>              nothing is left but the user's data
#
# And in a container, where systemd does not run:
#   installer.sh installed <deb or rpm>     as above, for either package
#   installer.sh links                      as above
#   installer.sh service-skipped <log>      the install left out the service and said
#                                           so in <log>, the package manager's output
#   installer.sh gone                       after a removal (a purge for the .deb),
#                                           nothing of the package is left
#
# The .rpm is also checked in a Fedora container that systemd runs, with
# prepare, installed, links, as-staged, who-can-change, service,
# status-as-user, remember-state, state-kept and gone.
#
# Each command stops with an error at the first thing that is wrong.
#
# Only for a throwaway CI runner, run as root: it installs packages and a
# root service and adds a user. The workflow sets
# UBC_VPN_TEST_THROWAWAY_MACHINE on GitHub's own runners only. Never run it
# on a machine that is kept.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }

[ "${UBC_VPN_TEST_THROWAWAY_MACHINE:-}" = 1 ] || fail "only for a throwaway CI runner"
[ "$(id -u)" = 0 ] || fail "run as root"
[ $# -ge 1 ] || fail "usage: installer.sh <command> [<argument>]"
command=$1
arg=${2:-}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

PACKAGE=ubc-vpn
APP="/opt/UBC VPN"
BIN="$APP/resources/bin"
SERVICE="$BIN/ubc-vpn-service"
CLIENT="$BIN/ubc-vpn"
LIBRARY="$BIN/libopenconnect.so.5"
UNIT=/etc/systemd/system/ubc-vpn.service
WANTS=/etc/systemd/system/multi-user.target.wants/ubc-vpn.service
STATE=/var/lib/ubc-vpn/state.json
SOCKET=/run/ubc-vpn/service.sock
# A made-up standard user, and the app's profile in that user's home, which
# no removal may touch.
USER_NAME=uvt-user
PROFILE="/home/$USER_NAME/.config/UBC VPN"

need_arg() { [ -n "$arg" ] || fail "$command needs an argument"; }

# What a package removal must take away, as well as the package's own files.
system_paths=(
    "$APP" /usr/bin/ubc-vpn /usr/bin/ubc-vpn-app /etc/alternatives/ubc-vpn-app
    /etc/apparmor.d/ubc-vpn-app "$UNIT" "$WANTS" /etc/ubc-vpn /var/lib/ubc-vpn /run/ubc-vpn
)
assert_gone() {
    local path file
    for path in "${system_paths[@]}"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || fail "$path is left"
    done
    # Every file and link the package had; folders such as /usr/bin stay.
    while IFS= read -r file; do
        [ -d "$file" ] && [ ! -L "$file" ] && continue
        [ ! -e "$file" ] && [ ! -L "$file" ] || fail "$file is left"
    done < "$1"
    [ "$(systemctl show -p LoadState --value ubc-vpn.service)" = not-found ] || fail "systemd still knows the unit"
    ! pgrep -x ubc-vpn-service > /dev/null || fail "the service still runs"
    [ -f "$PROFILE/marker" ] || fail "the user's app profile in $PROFILE was removed"
}

case "$command" in
    prepare)
        # GitHub's image leaves /opt open to everyone (0777, with an access
        # list), which the service rightly refuses, so on this throwaway
        # runner it is closed as a system's own /opt is.
        setfacl -b /opt
        chmod 0755 /opt
        useradd --create-home --shell /bin/bash "$USER_NAME"
        sudo -u "$USER_NAME" mkdir -p "$PROFILE"
        sudo -u "$USER_NAME" touch "$PROFILE/marker"
        echo "/opt is $(stat -c '%U %a' /opt); $USER_NAME has an app profile"
        ;;
    install)
        need_arg
        # What it depends on, from the runner's own package sources, then
        # the package itself, by dpkg alone, so its scripts' failures show.
        apt-get satisfy -y --no-install-recommends "$(dpkg-deb --field "$arg" Depends)"
        dpkg -i "$arg"
        echo "installed $(dpkg-query -W -f '${Package} ${Version} ${Status}' "$PACKAGE")"
        ;;
    installed)
        need_arg
        packaged=$(mktemp -d)
        case "$arg" in
            *.deb) dpkg-deb --extract "$arg" "$packaged" ;;
            *.rpm) rpm2cpio "$arg" | (cd "$packaged" && cpio --extract --make-directories --preserve-modification-time --quiet) ;;
            *) fail "not a .deb or .rpm: $arg" ;;
        esac
        count=0
        while IFS= read -r -d '' entry; do
            path=${entry#"$packaged"}
            installed=$path
            [ -n "$path" ] || continue
            if [ -L "$entry" ]; then
                [ -L "$installed" ] || fail "$installed is not a link"
                [ "$(readlink "$installed")" = "$(readlink "$entry")" ] || fail "$installed points elsewhere"
            elif [ -d "$entry" ]; then
                [ -d "$installed" ] && [ ! -L "$installed" ] || fail "$installed is not a folder"
            else
                [ -f "$installed" ] && [ ! -L "$installed" ] || fail "$installed is not a file"
                cmp -s "$entry" "$installed" || fail "$installed differs from the package"
                # The install script sets the sandbox helper's mode itself.
                if [ "$path" != "$APP/chrome-sandbox" ]; then
                    [ "$(stat -c %a "$installed")" = "$(stat -c %a "$entry")" ] || fail "$installed has mode $(stat -c %a "$installed")"
                fi
                count=$((count + 1))
            fi
        done < <(find "$packaged" -print0)
        # Nothing in the app's folder that the package did not bring.
        extra=$(comm -13 <(cd "$packaged$APP" && find . | sort) <(cd "$APP" && find . | sort))
        [ -z "$extra" ] || fail "in $APP but not in the package: $extra"
        rm -rf "$packaged"
        echo "all $count files are installed as packaged, and nothing else is in $APP"
        ;;
    as-staged)
        need_arg
        stage=$(cd "$arg" && pwd)
        for name in ubc-vpn-service ubc-vpn libopenconnect.so.5; do
            cmp "$stage/bin/$name" "$BIN/$name"
        done
        [ "$(ls -A "$BIN")" = "$(ls -A "$stage/bin")" ] || fail "$BIN holds other files than the stage"
        cmp "$stage/policy.json" "$APP/resources/policy.json"
        (cd "$stage/licenses" && find . -type f -print0) | while IFS= read -r -d '' file; do
            cmp "$stage/licenses/$file" "$APP/resources/licenses/$file"
        done
        [ "$(readlink /usr/bin/ubc-vpn)" = "$CLIENT" ] || fail "/usr/bin/ubc-vpn does not point to the client"
        echo "the programs, the library, its licences and the policy are as staged"
        ;;
    who-can-change)
        # The service's folder, every folder above it and every file in it:
        # real, root's, and writable by root alone. The service checks the
        # same when it starts (crates/platform/src/unix/program.rs).
        path=$BIN
        while :; do
            [ -d "$path" ] && [ ! -L "$path" ] || fail "$path is not a real folder"
            [ "$(stat -c %u "$path")" = 0 ] || fail "$path is not root's"
            [ $((0$(stat -c %a "$path") & 022)) = 0 ] || fail "$path can be changed by others ($(stat -c %a "$path"))"
            [ "$path" = / ] && break
            path=$(dirname "$path")
        done
        for file in "$BIN"/*; do
            [ -f "$file" ] && [ ! -L "$file" ] || fail "$file is not a file"
        done
        # The whole app: root's, and nothing others may change.
        open=$(find "$APP" \( ! -uid 0 -o ! -gid 0 -o -perm /022 \) -print)
        [ -z "$open" ] || fail "others can change: $open"
        echo "only root can change $BIN, the folders above it, and $APP"
        ;;
    no-rpath)
        for file in "$SERVICE" "$CLIENT" "$LIBRARY"; do
            dynamic=$(readelf -d "$file")
            echo "$file:"
            grep -E '\((NEEDED|RPATH|RUNPATH|SONAME)\)' <<<"$dynamic" || true
            # The list must be readable, or the next check would prove nothing.
            grep -q '(NEEDED)' <<<"$dynamic" || fail "readelf read nothing from $file"
            if grep -qE '\((RPATH|RUNPATH)\)' <<<"$dynamic"; then
                fail "$file has an rpath or runpath: the loader would search a folder no one checked"
            fi
        done
        # The library is loaded by its full path at run time, never linked.
        for file in "$SERVICE" "$CLIENT"; do
            ! readelf -d "$file" | grep -qF libopenconnect || fail "$file links libopenconnect"
        done
        echo "no rpath or runpath"
        ;;
    service)
        [ "$(systemctl is-active ubc-vpn.service)" = active ] || fail "the unit is $(systemctl is-active ubc-vpn.service)"
        [ "$(systemctl is-enabled ubc-vpn.service)" = enabled ] || fail "the unit is not enabled"
        cmp "$UNIT" "$repo/packaging/linux/ubc-vpn.service"
        pid=$(systemctl show -p MainPID --value ubc-vpn.service)
        [ "$pid" -gt 0 ] || fail "no main process"
        [ "$(readlink "/proc/$pid/exe")" = "$SERVICE" ] || fail "the unit runs $(readlink "/proc/$pid/exe")"
        cmp /etc/ubc-vpn/policy.json "$APP/resources/policy.json"
        [ -S "$SOCKET" ] || fail "nothing listens"
        echo "the unit runs $SERVICE with the package's policy"
        ;;
    status-as-user)
        # Through /usr/bin/ubc-vpn, with nothing of this script's environment.
        status=$(sudo -u "$USER_NAME" env -i HOME="/home/$USER_NAME" PATH=/usr/bin:/bin ubc-vpn status)
        [ "$status" = Disconnected ] || fail "status: $status"
        [ "$(stat -c '%u %a' "$SOCKET")" = "$(id -u "$USER_NAME") 600" ] || fail "$USER_NAME does not own the service"
        [ -f "$STATE" ] || fail "no $STATE"
        echo "$USER_NAME's ubc-vpn status said $status, and $USER_NAME owns the service"
        ;;
    remember-files)
        need_arg
        dpkg-query -L "$PACKAGE" > "$arg"
        echo "$(wc -l < "$arg") paths noted"
        ;;
    remember-state)
        need_arg
        [ -f "$STATE" ] || fail "no $STATE"
        sha256sum "$STATE" > "$arg"
        cat "$arg"
        ;;
    state-kept)
        need_arg
        [ -f "$STATE" ] || fail "$STATE is gone"
        sha256sum --check "$arg" || fail "$STATE changed"
        ;;
    no-conffiles)
        # policy.json goes to /etc/ubc-vpn through `install`; were a file a
        # conffile, dpkg could keep or ask about it on an update.
        listed=$(dpkg-query -W -f '${Conffiles}' "$PACKAGE")
        [ -z "$listed" ] || fail "dpkg keeps these as conffiles: $listed"
        echo "no conffiles"
        ;;
    scripts-twice)
        version=$(dpkg-query -W -f '${Version}' "$PACKAGE")
        for _ in 1 2; do
            "/var/lib/dpkg/info/$PACKAGE.prerm" upgrade "$version"
            "/var/lib/dpkg/info/$PACKAGE.postrm" upgrade "$version"
        done
        for _ in 1 2; do
            "/var/lib/dpkg/info/$PACKAGE.postinst" configure "$version"
        done
        [ "$(systemctl is-active ubc-vpn.service)" = active ] || fail "the unit is $(systemctl is-active ubc-vpn.service)"
        [ -e /usr/bin/ubc-vpn-app ] || fail "electron-builder's link to the app is gone"
        echo "the update scripts ran twice and the service runs"
        ;;
    remove)
        apt-get remove -y "$PACKAGE"
        ;;
    removed)
        need_arg
        assert_gone "$arg"
        [ "$(dpkg-query -W -f '${Status}' "$PACKAGE")" = "deinstall ok config-files" ] || fail "dpkg says $(dpkg-query -W -f '${Status}' "$PACKAGE")"
        # A removal's script is safe to run again.
        "/var/lib/dpkg/info/$PACKAGE.postrm" remove
        assert_gone "$arg"
        echo "nothing is left but the user's data in $PROFILE and dpkg's record"
        ;;
    purge)
        apt-get purge -y "$PACKAGE"
        ;;
    purged)
        need_arg
        assert_gone "$arg"
        status=$(dpkg-query -W -f '${Status}' "$PACKAGE" 2> /dev/null || true)
        [ -z "$status" ] || [[ $status == *" not-installed" ]] || fail "dpkg says $status"
        ! compgen -G "/var/lib/dpkg/info/$PACKAGE.*" > /dev/null || fail "dpkg's scripts for $PACKAGE are left"
        echo "nothing is left but the user's data in $PROFILE"
        ;;
    service-skipped)
        need_arg
        grep -qF "systemd is not running, so the UBC VPN service was not installed." "$arg" ||
            fail "the install did not say it left out the service"
        for path in "$UNIT" /etc/ubc-vpn /var/lib/ubc-vpn; do
            [ ! -e "$path" ] || fail "$path was made without systemd"
        done
        echo "without systemd, the service was left out and said so"
        ;;
    links)
        [ -L /usr/bin/ubc-vpn ] && [ "$(readlink /usr/bin/ubc-vpn)" = "$CLIENT" ] ||
            fail "/usr/bin/ubc-vpn is not a link to $CLIENT"
        # electron-builder's link, made by update-alternatives where there is
        # one, so through /etc/alternatives.
        [ -L /usr/bin/ubc-vpn-app ] && [ "$(readlink -f /usr/bin/ubc-vpn-app)" = "$APP/ubc-vpn-app" ] ||
            fail "/usr/bin/ubc-vpn-app is not a link to $APP/ubc-vpn-app"
        echo "/usr/bin/ubc-vpn and /usr/bin/ubc-vpn-app link to the client and the app"
        ;;
    gone)
        for path in "$APP" /usr/bin/ubc-vpn /usr/bin/ubc-vpn-app /etc/apparmor.d/ubc-vpn-app /etc/ubc-vpn /var/lib/ubc-vpn \
            "$UNIT" "$WANTS" /run/ubc-vpn; do
            [ ! -e "$path" ] && [ ! -L "$path" ] || fail "$path is left"
        done
        if command -v dpkg-query > /dev/null; then
            status=$(dpkg-query -W -f '${Status}' "$PACKAGE" 2> /dev/null || true)
            [ -z "$status" ] || [[ $status == *" not-installed" ]] || fail "dpkg says $status"
        else
            ! rpm -q "$PACKAGE" > /dev/null || fail "rpm still has $PACKAGE"
        fi
        echo "nothing of the package is left"
        ;;
    *)
        fail "unknown command: $command"
        ;;
esac
