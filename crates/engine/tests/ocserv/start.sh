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

# The one account, made up. The tests know it too.
TEST_USER=someone
TEST_PASSWORD=not-a-real-password

fail() { echo "error: $*" >&2; exit 1; }
[ $# -eq 1 ] || fail "usage: start.sh <folder>"
dir=$(cd "$1" && pwd)
[ -f "$dir/cert.pem" ] && [ -f "$dir/key.pem" ] || fail "no cert.pem and key.pem in $dir"
grep -q '^DISTRIB_CODENAME=jammy$' /etc/lsb-release || fail "this is not Ubuntu 22.04"

# ocserv and everything it needs come from a dated snapshot of the Ubuntu
# archive, at a pinned version, with its packaged service kept from ever
# starting: native/linux/test-packages.sh holds the pins and the checks.
root=$(cd "$(dirname "$0")/../../../.." && pwd)
bash "$root/native/linux/test-packages.sh" "$dir" ocserv
sudo systemctl disable ocserv.service
if systemctl is-active --quiet ocserv.service; then fail "the packaged ocserv service runs"; fi
if ss -Hltn 'sport = :443' | grep -q .; then fail "something listens on port 443"; fi

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
