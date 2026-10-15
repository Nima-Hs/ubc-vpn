#!/usr/bin/env bash
# Installs ocserv, a real AnyConnect-compatible gateway, and starts it on
# this machine for the engine's tests (tests/ocserv.rs).
#
# Only for a throwaway CI runner: it replaces the machine's package sources,
# installs a package as root and starts a root service. The engine workflow
# runs it on GitHub's own Ubuntu 22.04 runners only. Never run it on a
# machine that is kept.
#
# Usage: start.sh <folder>
#   <folder> holds cert.pem and key.pem, a throwaway key for
#   vpn.example.test. The configuration, the password file and the log are
#   written there too, and the port ocserv listens on, in the file "port".
set -euo pipefail

# ocserv and everything it needs come from this dated snapshot of the Ubuntu
# archive, at this exact version, so every run gets the same build.
APT_SNAPSHOT=20261011T000000Z
OCSERV_VERSION=1.1.3-1

# The one account, made up. The tests know it too.
TEST_USER=someone
TEST_PASSWORD=not-a-real-password

fail() { echo "error: $*" >&2; exit 1; }
[ $# -eq 1 ] || fail "usage: start.sh <folder>"
dir=$(cd "$1" && pwd)
[ -f "$dir/cert.pem" ] && [ -f "$dir/key.pem" ] || fail "no cert.pem and key.pem in $dir"
grep -q '^DISTRIB_CODENAME=jammy$' /etc/lsb-release || fail "this is not Ubuntu 22.04"

# Only the snapshot is asked: the machine's own sources are set aside for
# these commands, and apt must download nothing from anywhere else.
snapshot_url="https://snapshot.ubuntu.com/ubuntu/$APT_SNAPSHOT"
sources="$dir/snapshot.list"
cat > "$sources" <<EOF
deb $snapshot_url jammy main universe
deb $snapshot_url jammy-updates main universe
deb $snapshot_url jammy-security main universe
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
export DEBIAN_FRONTEND=noninteractive
# Fetches the package lists and sets `uris` to what apt would download. An
# empty list means the lists were not all fetched: that is tried again too.
list_downloads() {
    sudo apt-get "${apt_opts[@]}" update || return 1
    uris=$(sudo apt-get "${apt_opts[@]}" install -y --no-install-recommends --print-uris \
        "ocserv=$OCSERV_VERSION" | grep -o "^'[^']*'" | tr -d "'" || true)
    [ -n "$uris" ]
}
retry list_downloads
echo "Packages to download:"
echo "$uris"
stray=$(grep -v "^$snapshot_url/" <<<"$uris" || true)
[ -z "$stray" ] || fail "these packages are not from the snapshot: $stray"
# The package would start its own service, with its own settings, on every
# address at port 443. A policy-rc.d that refuses every start keeps it from
# ever running; it is removed once the package is in.
[ ! -e /usr/sbin/policy-rc.d ] || fail "/usr/sbin/policy-rc.d is already there"
printf '#!/bin/sh\nexit 101\n' | sudo tee /usr/sbin/policy-rc.d > /dev/null
sudo chmod 755 /usr/sbin/policy-rc.d
retry sudo apt-get "${apt_opts[@]}" install -y --no-install-recommends "ocserv=$OCSERV_VERSION"
sudo rm /usr/sbin/policy-rc.d
sudo systemctl disable ocserv.service
if systemctl is-active --quiet ocserv.service; then fail "the packaged ocserv service runs"; fi
if ss -Hltn 'sport = :443' | grep -q .; then fail "something listens on port 443"; fi
installed=$(dpkg-query -W -f '${Version}' ocserv)
[ "$installed" = "$OCSERV_VERSION" ] || fail "ocserv $installed is installed, not $OCSERV_VERSION"
echo "ocserv $installed from $snapshot_url"

printf '%s\n%s\n' "$TEST_PASSWORD" "$TEST_PASSWORD" | ocpasswd -c "$dir/ocpasswd" "$TEST_USER"

# A free port on this machine.
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')

# What the tunnel is given: made-up private addresses only. No UDP port,
# so no DTLS is offered.
cat > "$dir/ocserv.conf" <<EOF
auth = "plain[passwd=$dir/ocpasswd]"
listen-host = 127.0.0.1
tcp-port = $port
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ubc-vpn-test-ocserv.socket
pid-file = /run/ubc-vpn-test-ocserv.pid
server-cert = $dir/cert.pem
server-key = $dir/key.pem
max-clients = 8
max-same-clients = 8
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = false
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = false
device = ubcvpntest
predictable-ips = true
ipv4-network = 10.12.0.0
ipv4-netmask = 255.255.255.0
dns = 10.12.0.1
route = 10.13.0.0/255.255.0.0
mtu = 1400
cisco-client-compat = true
EOF

sudo ocserv --foreground --config "$dir/ocserv.conf" > "$dir/ocserv.log" 2>&1 &
for _ in $(seq 100); do
    if python3 -c "import socket; socket.create_connection(('127.0.0.1', $port), 1)" 2>/dev/null; then
        echo "$port" > "$dir/port"
        echo "ocserv listens on 127.0.0.1:$port"
        exit 0
    fi
    sleep 0.2
done
cat "$dir/ocserv.log" >&2
fail "ocserv did not start"
