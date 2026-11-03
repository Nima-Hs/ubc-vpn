#!/usr/bin/env bash
# Installs the service as the systemd unit on this machine with
# `ubc-vpn-service install`, as the Linux packages will, and checks the
# whole life of it: running, claimed by its first user and closed to
# others, reinstalled, connected through a real gateway under the hardened
# unit, stopped, and removed. Says "RAN: <name>" after each check that
# passed; the workflow requires every name in .github/ran/systemd/linux.
#
# Only for a throwaway CI runner, where systemd is PID 1: it installs a root
# service, adds a network namespace, a veth pair and a line to /etc/hosts,
# may link /etc/resolv.conf to systemd-resolved's stub, and starts ocserv as
# root. The workflow sets UBC_VPN_TEST_THROWAWAY_MACHINE
# on GitHub's own Ubuntu 22.04 runners only. Never run it on a machine that
# is kept, or one with UBC VPN installed.
#
# Usage: systemd.sh <folder>
#   The folder is made for the test's own files: the gateway's throwaway
#   key, its configuration and log, the policy and the client's settings.
# Needs:
#   - the release service and client, and libopenconnect.so.5, root's, in
#     /opt/UBC VPN/resources/bin, where the unit starts the service;
#   - ocserv installed by native/linux/test-packages.sh, its own service off;
#   - passwordless sudo.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }
ran() { echo "RAN: $1"; }

[ $# -eq 1 ] || fail "usage: systemd.sh <folder>"
[ "${UBC_VPN_TEST_THROWAWAY_MACHINE:-}" = 1 ] || fail "only for a throwaway CI runner"
[ -d /run/systemd/system ] || fail "systemd is not running"
grep -q '^DISTRIB_CODENAME=jammy$' /etc/lsb-release || fail "this is not Ubuntu 22.04"
mkdir "$1"
work=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

BIN="/opt/UBC VPN/resources/bin"
SERVICE="$BIN/ubc-vpn-service"
CLIENT="$BIN/ubc-vpn"
UNIT=/etc/systemd/system/ubc-vpn.service
WANTS=/etc/systemd/system/multi-user.target.wants/ubc-vpn.service
POLICY_DIR=/etc/ubc-vpn
STATE_DIR=/var/lib/ubc-vpn
SOCKET=/run/ubc-vpn/service.sock
# The routes' protocol number, LINUX_ROUTE_PROTOCOL.
PROTOCOL=181
# The gateway: in a namespace of its own behind a veth pair, so the service
# reaches it as it would a real one, through a network interface. The
# addresses are from the documentation range.
NAMESPACE=uvt-gateway
GATEWAY=192.0.2.1
HOST_SIDE=192.0.2.2
# The account the gateway knows, made up. connect.py answers with it.
TEST_USER=someone
TEST_PASSWORD=not-a-real-password

[ -x "$SERVICE" ] && [ -x "$CLIENT" ] || fail "no service and client in $BIN"
[ ! -e "$UNIT" ] && [ ! -e "$POLICY_DIR" ] && [ ! -e "$STATE_DIR" ] || fail "UBC VPN is installed here"

# The owner's and anyone else's view, as the CLI runs for each: nothing of
# this script's environment, and settings in the test's own folder.
client() {
    env -i HOME="$HOME" PATH=/usr/bin:/bin XDG_CONFIG_HOME="$work/config" "$CLIENT" "$@"
}
connect() {
    env -i HOME="$HOME" PATH=/usr/bin:/bin XDG_CONFIG_HOME="$work/config" \
        /usr/bin/python3 -I "$here/connect.py" "$CLIENT"
}
stranger() {
    sudo -u nobody env -i HOME=/nonexistent PATH=/usr/bin:/bin "$CLIENT" "$@"
}
run_service() {
    sudo /usr/bin/env -i "$SERVICE" "$@"
}
install_service() {
    run_service install --policy "$work/policy.json" "$@"
}
owner_and_mode() {
    sudo stat -c '%u:%g %a' "$1"
}
active() {
    systemctl is-active ubc-vpn.service || true
}
main_pid() {
    systemctl show -p MainPID --value ubc-vpn.service
}
# Waits up to <seconds> for <command> to succeed, or fails naming <what>.
within() {
    local limit=$1 what=$2
    shift 2
    for _ in $(seq $((limit * 5))); do
        if "$@"; then return 0; fi
        sleep 0.2
    done
    fail "$what"
}
# What ocserv logged, to its standard error and to syslog, with its passwords,
# its TLS chatter and anything as long as a cookie left out, as in engine.yml,
# though its account is made up.
ocserv_log() {
    { sudo cat "$work/ocserv.log"; sudo journalctl --no-pager -o short-precise -t ocserv; } |
        grep -viE 'password' | grep -vE 'TLS\[' |
        sed -E 's/[A-Za-z0-9+\/=_-]{16,}/[hidden]/g' | tail -n 100 || true
}
# Everything that could say why a connect the service took did not come up.
# The service's log is its own, already cleaned of secrets.
why_not_connected() {
    local pid task
    echo "--- why the service did not connect ---"
    echo "client status:"
    client status 2>&1 || true
    echo "client diagnostics:"
    client diagnostics 2>&1 || true
    echo "the service's log:"
    client logs --json 2>&1 || true
    echo "the service's threads, as state, what each waits in, and its name:"
    pid=$(main_pid)
    for task in "/proc/$pid/task/"*; do
        sudo sh -c "cut -d' ' -f3 '$task/stat'; cat '$task/wchan'; echo; cat '$task/comm'" 2>&1 |
            paste -s -d' ' || true
    done
    echo "the links, routes and connections:"
    ip -o link show || true
    ip -4 route show table all || true
    sudo ss -tnp || true
    echo "systemd-resolved is $(systemctl is-active systemd-resolved.service || true)," \
        "resolv.conf mode $(resolv_conf_mode || true)"
    ls -l /etc/resolv.conf || true
    echo "the service's journal:"
    journalctl -u ubc-vpn.service -o short-precise --no-pager | tail -n 50 || true
    echo "ocserv's log:"
    ocserv_log
    echo "--- end ---"
}
# Waits up to a minute for the connect just asked for, saying each state it
# sees and when, and everything known if it does not come.
wait_connected() {
    local seen="" now
    for _ in $(seq $((60 * 5))); do
        now=$(client status 2>&1 || true)
        if [ "$now" != "$seen" ]; then
            echo "$(date -u +%H:%M:%S.%3N) status: $now"
            seen=$now
        fi
        if printf '%s\n' "$now" | grep -q '^Connected (ubcvpn'; then return 0; fi
        # A connect that failed stays failed: nothing is retried.
        case "$now" in Failed:* | "Login needed"*) break ;; esac
        sleep 0.2
    done
    why_not_connected
    fail "the service did not connect"
}
# Whether programs ask systemd-resolved, as resolved itself says, such as
# s "stub".
resolv_conf_mode() {
    busctl get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 \
        org.freedesktop.resolve1.Manager ResolvConfMode
}
tunnel_links() {
    ip -o link show | grep -o 'ubcvpn[0-9]*' || true
}
# Every route of the product's, in every table, and any to the chosen subnet.
our_routes() {
    ip -4 route show table all proto "$PROTOCOL"
    ip -4 route show table all 198.19.0.0/16
}
stopped_lines() {
    journalctl -u ubc-vpn.service -o cat --no-pager | grep -c ' has stopped$' || true
}
nothing_runs() {
    ! pgrep -x ubc-vpn-service > /dev/null
}

# --- What programs ask ------------------------------------------------------

# The service refuses split DNS where programs do not ask systemd-resolved.
# Most of GitHub's runners link resolv.conf to its stub, but some have a plain
# file, which it counts as foreign, as the platform crate's DNS tests also find.
# The connect below would rightly fail there, so a runner like that is made like
# the others. The stub answers the runner's own lookups as before.
echo "resolv.conf mode: $(resolv_conf_mode)"
case "$(resolv_conf_mode)" in
's "stub"' | 's "static"') ;;
*)
    sudo ln -sfn ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    [ "$(resolv_conf_mode)" = 's "stub"' ] || fail "resolv.conf mode: $(resolv_conf_mode)"
    echo "resolv.conf linked to the stub"
    ;;
esac

# --- The gateway ------------------------------------------------------------

cd "$work"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=vpn.example.test" \
    -addext "subjectAltName=DNS:vpn.example.test" -keyout key.pem -out cert.pem 2> /dev/null
pin=$(openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary | base64)
printf '{"gateway":"vpn.example.test","pins":["pin-sha256:%s"]}\n' "$pin" > policy.json
printf '%s\n%s\n' "$TEST_PASSWORD" "$TEST_PASSWORD" | ocpasswd -c "$work/ocpasswd" "$TEST_USER"

sudo ip netns add "$NAMESPACE"
sudo ip link add uvt-gw0 type veth peer name uvt-gw1
sudo ip link set uvt-gw1 netns "$NAMESPACE"
sudo ip addr add "$HOST_SIDE/24" dev uvt-gw0
sudo ip link set uvt-gw0 up
sudo ip netns exec "$NAMESPACE" ip addr add "$GATEWAY/24" dev uvt-gw1
sudo ip netns exec "$NAMESPACE" ip link set uvt-gw1 up
sudo ip netns exec "$NAMESPACE" ip link set lo up
echo "$GATEWAY vpn.example.test" | sudo tee -a /etc/hosts > /dev/null

# As tests/ocserv/start.sh in the engine sets it up, on the gateway's
# address and port 443. Its device is not named like the product's.
cat > ocserv.conf <<EOF
auth = "plain[passwd=$work/ocpasswd]"
listen-host = $GATEWAY
tcp-port = 443
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ubc-vpn-test-systemd-ocserv.socket
pid-file = /run/ubc-vpn-test-systemd-ocserv.pid
server-cert = $work/cert.pem
server-key = $work/key.pem
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
device = uvtgw
predictable-ips = true
ipv4-network = 198.18.0.0
ipv4-netmask = 255.255.255.0
dns = 198.18.0.1
route = 198.19.0.0/255.255.0.0
mtu = 1400
cisco-client-compat = true
EOF
sudo ip netns exec "$NAMESPACE" ocserv --foreground --config "$work/ocserv.conf" > ocserv.log 2>&1 &
gateway_listens() {
    /usr/bin/python3 -I -c "import socket; socket.create_connection(('$GATEWAY', 443), 1)" 2> /dev/null
}
within 20 "ocserv did not start" gateway_listens
echo "ocserv listens on $GATEWAY:443"

# --- 1. Install -------------------------------------------------------------

install_service --fresh
[ "$(owner_and_mode "$UNIT")" = "0:0 644" ] || fail "the unit is $(owner_and_mode "$UNIT")"
cmp "$UNIT" "$repo/packaging/linux/ubc-vpn.service"
[ "$(owner_and_mode "$POLICY_DIR")" = "0:0 755" ] || fail "the policy folder"
[ "$(owner_and_mode "$POLICY_DIR/policy.json")" = "0:0 644" ] || fail "the policy"
cmp "$POLICY_DIR/policy.json" policy.json
[ "$(owner_and_mode "$STATE_DIR")" = "0:0 700" ] || fail "the state folder"
ran "install"

# --- 2. The unit runs, as the unit says -------------------------------------

[ "$(active)" = active ] || fail "the unit is $(active)"
[ "$(systemctl is-enabled ubc-vpn.service)" = enabled ] || fail "the unit is not enabled"
[ -L "$WANTS" ] || fail "the unit does not start with the system"
pid=$(main_pid)
[ "$pid" -gt 0 ] || fail "no main process"
[ "$(sudo readlink "/proc/$pid/exe")" = "$SERVICE" ] || fail "the unit runs another program"
[ "$(owner_and_mode /run/ubc-vpn)" = "0:0 755" ] || fail "the runtime folder"
sudo test -S "$SOCKET" || fail "nothing listens"
# What systemd applied: CAP_CHOWN (0) and CAP_NET_ADMIN (12) alone, and no
# new privileges.
sudo grep -qx $'CapBnd:\t0000000000001001' "/proc/$pid/status" || fail "the capabilities"
sudo grep -qx $'NoNewPrivs:\t1' "/proc/$pid/status" || fail "new privileges are allowed"
ran "running"

# --- 3. The first user to ask owns it ---------------------------------------

[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
[ "$(sudo stat -c '%u %a' "$SOCKET")" = "$(id -u) 600" ] || fail "the socket is $(sudo stat -c '%u %a' "$SOCKET")"
ran "owner"

# --- 4. Anyone else is refused ----------------------------------------------

status=0
stranger status > stranger.txt 2>&1 || status=$?
cat stranger.txt
[ "$status" = 5 ] || fail "another user was not refused as not the owner (status $status)"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "stranger refused"

# --- 5. Installing again keeps the owner ------------------------------------

state=$(sudo sha256sum "$STATE_DIR/state.json")
before=$(main_pid)
install_service
[ "$(sudo sha256sum "$STATE_DIR/state.json")" = "$state" ] || fail "an update changed state.json"
[ "$(main_pid)" != "$before" ] || fail "an update did not start the service again"
# A fresh install after an update that failed and was undone keeps it too.
install_service --fresh
[ "$(sudo sha256sum "$STATE_DIR/state.json")" = "$state" ] || fail "a fresh install reset the owner"
[ "$(active)" = active ] || fail "the unit is $(active)"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
status=0
stranger status > /dev/null 2>&1 || status=$?
[ "$status" = 5 ] || fail "another user was not refused after the install"
ran "reinstall keeps state"

# --- 6. A tunnel device, under the hardened unit ----------------------------

echo '{"subnets":["198.19.0.0/16"],"dns_domains":["dept.example.test"]}' |
    client settings set-routes --json
connect || fail "the connect was refused"
wait_connected
client status
link=$(tunnel_links | head -n 1)
[ -n "$link" ] || fail "no tunnel device"
ip -4 route show 198.19.0.0/16 | grep -q "dev $link" || fail "the subnet is not routed into $link"
resolvectl domain "$link" | grep -q 'dept.example.test' || fail "no split DNS on $link"
# The device is the service's own, opened inside the unit.
pid=$(main_pid)
sudo find "/proc/$pid/fd" -lname /dev/net/tun | grep -q . || fail "the service holds no tun device"
ran "device under the unit"

# --- 7. Stopping removes everything it applied ------------------------------

stops=$(stopped_lines)
sudo systemctl stop ubc-vpn.service
[ "$(active)" = inactive ] || fail "the unit is $(active)"
[ -z "$(tunnel_links)" ] || fail "a tunnel device is left: $(tunnel_links)"
[ -z "$(our_routes)" ] || fail "routes are left: $(our_routes)"
[ ! -e /run/ubc-vpn ] || fail "the runtime folder is left"
# It ended by itself, after its teardown, and was not killed.
[ "$(stopped_lines)" -gt "$stops" ] || fail "the service did not stop by itself"
sudo systemctl start ubc-vpn.service
within 60 "the service did not start again" sudo test -S "$SOCKET"
ran "stop tears down"

# --- 8. Uninstalling with --keep-data ---------------------------------------

run_service uninstall --keep-data
[ ! -e "$UNIT" ] && [ ! -e "$WANTS" ] || fail "the unit is left"
nothing_runs || fail "the service still runs"
sudo test -f "$STATE_DIR/state.json" || fail "the state was removed"
[ -f "$POLICY_DIR/policy.json" ] || fail "the policy was removed"
install_service
[ "$(sudo sha256sum "$STATE_DIR/state.json")" = "$state" ] || fail "the owner was lost"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "uninstall keeps data when asked"

# --- 9. A state folder anyone could have made is emptied --------------------

run_service uninstall
sudo mkdir -m 0777 "$STATE_DIR"
echo '{"owner":"65534"}' | sudo tee "$STATE_DIR/state.json" > /dev/null
sudo chmod 0666 "$STATE_DIR/state.json"
# An update refuses it, and registers nothing.
if install_service 2> refused.txt; then fail "an update took a state folder others can change"; fi
cat refused.txt
[ ! -e "$UNIT" ] || fail "an update that failed registered the service"
install_service --fresh
! sudo test -e "$STATE_DIR/state.json" || fail "the planted state.json is still there"
[ "$(owner_and_mode "$STATE_DIR")" = "0:0 700" ] || fail "the state folder"
[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
[ "$(sudo stat -c '%u %a' "$SOCKET")" = "$(id -u) 600" ] || fail "the planted owner kept it"
ran "planted state emptied"

# --- 10. Uninstalling while connected leaves nothing ------------------------

connect || fail "the connect was refused"
wait_connected
stops=$(stopped_lines)
run_service uninstall
nothing_runs || fail "the service still runs"
[ "$(stopped_lines)" -gt "$stops" ] || fail "the service did not stop by itself"
for path in "$UNIT" "$WANTS" "$POLICY_DIR" /run/ubc-vpn; do
    [ ! -e "$path" ] || fail "$path is left"
done
! sudo test -e "$STATE_DIR" || fail "$STATE_DIR is left"
[ "$(systemctl show -p LoadState --value ubc-vpn.service)" = not-found ] || fail "systemd still knows the unit"
[ -z "$(tunnel_links)" ] || fail "a tunnel device is left: $(tunnel_links)"
[ -z "$(our_routes)" ] || fail "routes are left: $(our_routes)"
ran "uninstall leaves nothing"
