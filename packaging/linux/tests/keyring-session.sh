#!/usr/bin/env bash
# Starts a desktop session's bus and a real Secret Service (gnome-keyring), and
# runs app/tests/session/keyring.test.ts in it against the installed client.
#
# As the runner's ordinary user, from the app folder, once the package is
# installed. gnome-keyring is installed by native/linux/test-packages.sh; the
# bus's dbus-daemon comes with the runner's image.
#
# Only for a throwaway CI runner. The session's folders are new, and the
# keyring's password is made up for the run and protects nothing.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }

[ "${UBC_VPN_TEST_THROWAWAY_MACHINE:-}" = 1 ] || fail "only for a throwaway CI runner"
[ "$(id -u)" != 0 ] || fail "run as an ordinary user"

CLIENT="/opt/UBC VPN/resources/bin/ubc-vpn"
[ -x "$CLIENT" ] || fail "$CLIENT is not installed"

work=$(mktemp -d)
daemon=
stop() {
    [ -z "$daemon" ] || kill "$daemon" 2> /dev/null || true
    pkill -u "$(id -u)" -x gnome-keyring-d 2> /dev/null || true
    rm -rf "$work"
}
trap stop EXIT

# A session's own: nothing of the runner's reaches the keyring or the client.
export HOME="$work/home"
export XDG_RUNTIME_DIR="$work/run"
unset XDG_CONFIG_HOME XDG_DATA_HOME
mkdir "$HOME"
mkdir -m 700 "$XDG_RUNTIME_DIR"

# Where a systemd session has it, so both ways of finding it can be tried.
address="unix:path=$XDG_RUNTIME_DIR/bus"
dbus-daemon --session --nofork --nopidfile --address="$address" &
daemon=$!
for _ in $(seq 50); do
    [ -S "$XDG_RUNTIME_DIR/bus" ] && break
    sleep 0.1
done
[ -S "$XDG_RUNTIME_DIR/bus" ] || fail "the session's bus did not start"
export DBUS_SESSION_BUS_ADDRESS="$address"

# The keyring a sign-in unlocks: a new login keyring, with a made-up password.
printf 'made-up-keyring-password' |
    gnome-keyring-daemon --daemonize --login --components=secrets > /dev/null
gnome-keyring-daemon --daemonize --start --components=secrets > /dev/null
for _ in $(seq 50); do
    if dbus-send --session --print-reply --dest=org.freedesktop.DBus / \
        org.freedesktop.DBus.GetNameOwner string:org.freedesktop.secrets > /dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
dbus-send --session --print-reply --dest=org.freedesktop.DBus / \
    org.freedesktop.DBus.GetNameOwner string:org.freedesktop.secrets > /dev/null ||
    fail "the Secret Service did not start"

export UBC_VPN_SESSION_CLIENT="$CLIENT"
./node_modules/.bin/vitest run --config vitest.session.config.ts
