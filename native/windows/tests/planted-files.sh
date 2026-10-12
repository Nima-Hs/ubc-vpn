#!/usr/bin/env bash
# Plants hostile GnuTLS configuration files where MSYS2's stock GnuTLS was seen
# to read them, and names them in the environment variable GnuTLS reads, then
# checks that the build output ignores them.
#
# Every case is also tried on the stock GnuTLS (work/control, from control.sh),
# which must break. Without that, a pass here would prove nothing.
#
# Run from Git Bash as an administrator, after the probe has been built, a
# certificate made and wintun.dll put beside the probe (see ../probe).
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
probe=$here/../probe
ours=$here/out/bin
control=$here/work/control/bin
windows=/c/Windows/System32:/c/Windows
port=4460

cd "$probe"
drive=$(pwd | cut -c1-2) # the current drive, as /d

# run <dll folder> <mode> [args]: runs the probe against a fresh fake gateway,
# with only that folder and Windows on PATH. Output goes to run.txt.
run() {
    local dlls=$1 mode=$2 status=0
    shift 2
    port=$((port + 1))
    python fake_server.py cert.pem key.pem "$port" >/dev/null 2>&1 &
    sleep 3
    PATH="$dlls:$windows" ./target/release/oc-probe.exe "$mode" "https://127.0.0.1:$port" "$@" >run.txt 2>&1 || status=$?
    kill $! 2>/dev/null || true
    return "$status"
}

fail() {
    cat run.txt
    echo "FAILED: $*"
    exit 1
}

# The output must pass both modes; the control must fail to make a connection.
ours_must_pass() {
    run "$ours" probe || fail "the output's probe fails $1"
    grep -qx 'RESULT: PASS' run.txt || fail "the output's probe did not pass $1"
    run "$ours" connect testuser testpass || fail "the output's connect fails $1"
    grep -qx 'RESULT: PASS' run.txt || fail "the output's connect did not pass $1"
    echo "output: probe and connect pass $1"
}
control_must_fail() {
    if run "$control" probe; then
        fail "the control still passes $1, so this case shows nothing"
    fi
    grep -q -E 'SSL connection failure|Failed to set GnuTLS priority string' run.txt ||
        fail "the control failed $1, but not while setting up TLS"
    echo "control: fails $1: $(grep -E 'SSL connection failure|Failed to set GnuTLS priority string' run.txt | head -1 | sed 's/^ *//' | cut -c1-120)"
}

# plant <file> <line>...: writes the file, remembering what to remove afterwards.
created=()
cleanup() {
    [ ${#created[@]} -eq 0 ] || rm -rf "${created[@]}"
}
trap cleanup EXIT
plant() {
    local file=$1 top=$1
    shift
    while [ ! -e "$(dirname "$top")" ]; do
        top=$(dirname "$top")
    done
    [ -e "$top" ] || created+=("$top")
    mkdir -p "$(dirname "$file")"
    printf '%s\n' "$@" >"$file"
    echo "planted $file"
}

# Two hostile configurations. Either stops any TLS handshake by a library that
# reads it. The first turns off every cipher and key exchange and replaces the
# default priorities; upstream GnuTLS obeys these even when built without a
# system configuration file. The second adds the protocol versions, which is
# what the first version of this test relied on.
ciphers=(AES-128-GCM AES-256-GCM CHACHA20-POLY1305 AES-128-CCM AES-256-CCM AES-128-CCM-8 AES-256-CCM-8
    AES-128-CBC AES-256-CBC 3DES-CBC CAMELLIA-128-GCM CAMELLIA-256-GCM CAMELLIA-128-CBC CAMELLIA-256-CBC)
exchanges=(RSA DHE-RSA ECDHE-RSA ECDHE-ECDSA DHE-DSS PSK DHE-PSK ECDHE-PSK RSA-PSK ANON-DH ANON-ECDH)
no_ciphers=("[overrides]" "default-priority-string = NONE"
    "${ciphers[@]/#/tls-disabled-cipher = }" "${exchanges[@]/#/tls-disabled-kx = }")
no_versions=("${no_ciphers[@]}" "disabled-version = tls1.0" "disabled-version = tls1.1"
    "disabled-version = tls1.2" "disabled-version = tls1.3")

echo "--- With nothing planted, the output and the control must both work"
run "$ours" probe || fail "the output does not pass the probe"
run "$control" probe || fail "the control does not pass the probe, so it cannot show anything"

echo "--- A configuration named by GNUTLS_SYSTEM_PRIORITY_FILE"
plant "$here/work/control/no-ciphers" "${no_ciphers[@]}"
plant "$here/work/control/no-versions" "${no_versions[@]}"
for name in no-ciphers no-versions; do
    GNUTLS_SYSTEM_PRIORITY_FILE=$(cygpath -w "$here/work/control/$name")
    export GNUTLS_SYSTEM_PRIORITY_FILE
    ours_must_pass "with the variable naming $name"
    control_must_fail "with the variable naming $name"
    unset GNUTLS_SYSTEM_PRIORITY_FILE
done

echo "--- Configurations at the paths the stock library looks in, and their neighbours"
for file in /d/M/msys64/ucrt64/etc/gnutls/config /c/etc/gnutls/config "$drive/etc/gnutls/config" \
    /c/ucrt64/etc/gnutls/config "$drive/ucrt64/etc/gnutls/config" "$here/out/etc/gnutls/config"; do
    plant "$file" "${no_versions[@]}"
done
ours_must_pass "with the files planted"
control_must_fail "with the files planted"
