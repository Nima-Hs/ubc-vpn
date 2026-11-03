#!/usr/bin/env bash
# Installs the service as the launchd daemon on this machine with
# `ubc-vpn-service install`, as the macOS package will, and checks the whole
# life of it: running, claimed by its first user and closed to others,
# reinstalled, killed and started again by launchd, stopped, disabled and
# reinstalled, and removed. Says "RAN: <name>" after each check that passed;
# the workflow requires every name in .github/ran/launchd/macos.
#
# Only for a throwaway CI runner: it installs a root service and changes
# /Library. The workflow sets UBC_VPN_TEST_THROWAWAY_MACHINE on GitHub's own
# runners only. Never run it on a machine that is kept, or one with UBC VPN
# installed.
#
# Nothing connects: no gateway runs on the macOS runner, so routes and DNS
# being removed at a real stop are shown elsewhere.
#
# Usage: launchd.sh <folder>
#   The folder is made for the test's own files: the policy and the client's
#   settings.
# Needs:
#   - the release service and client, and the libraries, root's, in
#     /Library/PrivilegedHelperTools/io.github.nima-hs.ubc-vpn;
#   - passwordless sudo.
# Runs on macOS's bash 3.2.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }
ran() { echo "RAN: $1"; }

[ $# -eq 1 ] || fail "usage: launchd.sh <folder>"
[ "${UBC_VPN_TEST_THROWAWAY_MACHINE:-}" = 1 ] || fail "only for a throwaway CI runner"
[ "$(uname)" = Darwin ] || fail "this is not macOS"
mkdir "$1"
work=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

LABEL=io.github.nima-hs.ubc-vpn
JOB=system/$LABEL
FOLDER=/Library/PrivilegedHelperTools/$LABEL
SERVICE=$FOLDER/ubc-vpn-service
CLIENT=$FOLDER/ubc-vpn
PLIST=/Library/LaunchDaemons/$LABEL.plist
DATA="/Library/Application Support/UBC VPN"
SOCKET=$DATA/service.sock
STATE=$DATA/state.json
LOG=$DATA/service.log

[ -x "$SERVICE" ] && [ -x "$CLIENT" ] || fail "no service and client in $FOLDER"
[ ! -e "$PLIST" ] && [ ! -e "$DATA" ] || fail "UBC VPN is installed here"

printf '{"gateway":"vpn.example.test","pins":["pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]}\n' \
    > "$work/policy.json"

# The owner's and anyone else's view, as the app runs the client: nothing of
# this script's environment.
client() {
    env -i HOME="$work/home" PATH=/usr/bin:/bin "$CLIENT" "$@"
}
mkdir "$work/home"
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
    sudo stat -f '%u:%g %Lp' "$1"
}
# launchd's view of the job, or nothing when it does not know it.
print_job() {
    sudo launchctl print "$JOB" 2> /dev/null || true
}
# A setting of the job itself: the lines one tab in.
job_setting() {
    print_job | sed -n "s/^	$1 = //p" | head -n 1
}
pid_now() {
    job_setting pid
}
sha() {
    sudo shasum -a 256 "$1"
}
# Waits up to <seconds> for <command> to succeed, or fails naming <what>.
within() {
    local limit=$1 what=$2 _n=0
    shift 2
    while [ "$_n" -lt $((limit * 5)) ]; do
        if "$@"; then return 0; fi
        sleep 0.2
        _n=$((_n + 1))
    done
    fail "$what"
}
stopped_lines() {
    sudo grep -c ' has stopped$' "$LOG" || true
}
nothing_runs() {
    ! pgrep -x ubc-vpn-service > /dev/null
}
answers() {
    [ "$(client status 2> /dev/null)" = Disconnected ]
}
new_pid() {
    local now
    now=$(pid_now)
    [ -n "$now" ] && [ "$now" != "$1" ]
}

# What is on the way to the service, for the record.
ls -ldn / /Library /Library/PrivilegedHelperTools /Library/LaunchDaemons "$FOLDER" "/Library/Application Support"
ls -ln "$FOLDER"

# --- 1. Install -------------------------------------------------------------

install_service --fresh
[ "$(owner_and_mode "$PLIST")" = "0:0 644" ] || fail "the job is $(owner_and_mode "$PLIST")"
cmp "$PLIST" "$repo/packaging/macos/$LABEL.plist"
plutil -lint "$PLIST"
[ "$(plutil -extract ProgramArguments.0 raw "$PLIST")" = "$SERVICE" ] || fail "the job's program"
[ "$(plutil -extract ExitTimeOut raw "$PLIST")" = 30 ] || fail "the job's ExitTimeOut"
[ "$(owner_and_mode "$DATA")" = "0:0 755" ] || fail "the data folder"
[ "$(owner_and_mode "$DATA/policy.json")" = "0:0 644" ] || fail "the policy"
cmp "$DATA/policy.json" "$work/policy.json"
# Nothing is marked for launchd unless someone marked it.
if sudo launchctl print-disabled system | grep -F "\"$LABEL\""; then
    fail "the install left a record in launchd's list of disabled jobs"
fi
ran "install"

# --- 2. launchd runs it, as the job says ------------------------------------

print_job
[ "$(job_setting state)" = running ] || fail "the job is $(job_setting state)"
[ "$(job_setting program)" = "$SERVICE" ] || fail "launchd runs $(job_setting program)"
[ "$(job_setting 'exit timeout')" = 30 ] || fail "launchd's exit timeout is $(job_setting 'exit timeout')"
pid=$(pid_now)
[ -n "$pid" ] || fail "no process"
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = root ] || fail "the service does not run as root"
[ "$(ps -o comm= -p "$pid")" = "$SERVICE" ] || fail "launchd runs another program"
[ -S "$SOCKET" ] || fail "nothing listens"
sudo grep -q 'is running' "$LOG" || fail "the log does not say the service runs"
# launchd makes the log with the job's umask, and only root may change it.
log_mode=$(owner_and_mode "$LOG")
echo "The log is $log_mode"
case $log_mode in
    "0:0 600" | "0:0 640" | "0:0 644") ;;
    *) fail "the log is $log_mode" ;;
esac
ran "running"

# --- 3. The first user to ask owns it ---------------------------------------

[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
[ "$(sudo stat -f '%u %Lp' "$SOCKET")" = "$(id -u) 600" ] || fail "the socket is $(sudo stat -f '%u %Lp' "$SOCKET")"
sudo grep -q owner "$STATE" || fail "no owner in state.json"
ran "owner"

# --- 4. Anyone else is refused ----------------------------------------------

status=0
stranger status > "$work/stranger.txt" 2>&1 || status=$?
cat "$work/stranger.txt"
[ "$status" = 5 ] || fail "another user was not refused as not the owner (status $status)"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "stranger refused"

# --- 5. Installing again keeps the owner ------------------------------------

state=$(sha "$STATE")
before=$(pid_now)
stops=$(stopped_lines)
install_service
[ "$(sha "$STATE")" = "$state" ] || fail "an update changed state.json"
[ "$(pid_now)" != "$before" ] || fail "an update did not start the service again"
# It ended by itself, after its teardown, and was not killed.
[ "$(stopped_lines)" -gt "$stops" ] || fail "the old service did not stop by itself"
# A fresh install after an update that failed and was undone keeps it too.
install_service --fresh
[ "$(sha "$STATE")" = "$state" ] || fail "a fresh install reset the owner"
[ "$(job_setting state)" = running ] || fail "the job is $(job_setting state)"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
status=0
stranger status > /dev/null 2>&1 || status=$?
[ "$status" = 5 ] || fail "another user was not refused after the install"
ran "reinstall keeps state"

# --- 6. launchd starts it again after it fails ------------------------------

before=$(pid_now)
sudo kill -9 "$before"
within 30 "launchd did not start the service again" new_pid "$before"
within 30 "the service did not listen again" answers
[ "$(sha "$STATE")" = "$state" ] || fail "a crash changed state.json"
ran "restarted after a crash"

# --- 7. A stop ends it for good, and the client's command starts it again ---

stops=$(stopped_lines)
sudo launchctl kill SIGTERM "$JOB"
gone() { [ "$(job_setting state)" != running ]; }
within 40 "the service did not stop" gone
sleep 8
[ "$(job_setting state)" != running ] || fail "launchd started a service that was asked to stop"
[ "$(stopped_lines)" -gt "$stops" ] || fail "the service did not stop by itself"
[ ! -S "$SOCKET" ] || fail "the socket is left"
status=0
client status > "$work/stopped.txt" 2>&1 || status=$?
cat "$work/stopped.txt"
[ "$status" = 3 ] || fail "the client did not say the service is stopped (status $status)"
grep -qF "launchctl kickstart -k $JOB" "$work/stopped.txt" || fail "the client names another job"
sudo launchctl kickstart -k "$JOB"
within 30 "the client's command did not start the service" answers
ran "stop and start again"

# --- 8. A job someone disabled is enabled by installing ---------------------

sudo launchctl disable "$JOB"
sudo launchctl print-disabled system | grep -F "\"$LABEL\""
install_service
[ "$(job_setting state)" = running ] || fail "the job is $(job_setting state)"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "disabled job enabled"

# --- 9. Uninstalling with --keep-data ---------------------------------------

stops=$(stopped_lines)
run_service uninstall --keep-data
[ ! -e "$PLIST" ] || fail "the job's file is left"
[ -z "$(print_job)" ] || fail "launchd still knows the job"
nothing_runs || fail "the service still runs"
[ "$(stopped_lines)" -gt "$stops" ] || fail "the service did not stop by itself"
sudo test -f "$STATE" || fail "the state was removed"
[ -f "$DATA/policy.json" ] || fail "the policy was removed"
# Twice is fine, as for a script run again.
run_service uninstall --keep-data
install_service
[ "$(sha "$STATE")" = "$state" ] || fail "the owner was lost"
[ "$(client status)" = Disconnected ] || fail "the owner lost it"
ran "uninstall keeps data when asked"

# --- 10. A service anywhere else is not registered --------------------------

elsewhere=/Library/PrivilegedHelperTools/uvt-elsewhere
sudo mkdir -m 755 "$elsewhere"
sudo cp -p "$SERVICE" "$elsewhere/"
pid=$(pid_now)
if sudo /usr/bin/env -i "$elsewhere/ubc-vpn-service" install --policy "$work/policy.json" 2> "$work/refused.txt"; then
    fail "a service elsewhere was registered"
fi
cat "$work/refused.txt"
grep -qF "only from $SERVICE" "$work/refused.txt" || fail "it was refused for another reason"
[ "$(pid_now)" = "$pid" ] || fail "the refused install stopped the service"
sudo rm -rf "$elsewhere"
ran "elsewhere refused"

# --- 11. A data folder anyone could have made is emptied --------------------

run_service uninstall
[ ! -e "$DATA" ] || fail "the data folder is left"
sudo mkdir -m 0777 "$DATA"
echo '{"owner":"-2"}' | sudo tee "$STATE" > /dev/null
sudo chmod 0666 "$STATE"
# An update refuses it, and registers nothing.
if install_service 2> "$work/refused.txt"; then fail "an update took a data folder others can change"; fi
cat "$work/refused.txt"
[ ! -e "$PLIST" ] || fail "an update that failed registered the service"
install_service --fresh
sudo test ! -e "$STATE" || fail "the planted state.json is still there"
[ "$(owner_and_mode "$DATA")" = "0:0 755" ] || fail "the data folder"
[ "$(client status)" = Disconnected ] || fail "status: $(client status)"
[ "$(sudo stat -f '%u %Lp' "$SOCKET")" = "$(id -u) 600" ] || fail "the planted owner kept it"
ran "planted state emptied"

# --- 12. Uninstalling leaves nothing ----------------------------------------

run_service uninstall
nothing_runs || fail "the service still runs"
for path in "$PLIST" "$DATA"; do
    [ ! -e "$path" ] || fail "$path is left"
done
[ -z "$(print_job)" ] || fail "launchd still knows the job"
status=0
sudo launchctl print "$JOB" > /dev/null 2>&1 || status=$?
[ "$status" = 113 ] || fail "launchctl says $status of a job it does not know"
# Removing what is not there is fine.
run_service uninstall
ran "uninstall leaves nothing"
