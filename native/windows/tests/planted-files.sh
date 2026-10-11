#!/usr/bin/env bash
# Plants hostile configuration files in every place MSYS2's stock GnuTLS and
# p11-kit were seen to read, then checks that the build output ignores them.
#
# The same files are tried on the stock GnuTLS (work/control, from control.sh),
# which must break. Without that, a pass here would prove nothing.
#
# Run from Git Bash as an administrator, after the probe has been built, a
# certificate made and wintun.dll put beside the probe (see ../probe).
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
probe=$here/../probe
ours=$here/out/bin
control=$here/work/control/bin
marker=$here/work/control/marker.dll
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

# plant <file> <line>...: writes the file, remembering what to remove afterwards.
created=()
cleanup() {
    [ ${#created[@]} -eq 0 ] || rm -rf "${created[@]}"
    rm -f "$marker.loaded"
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

echo "--- Before planting: both the output and the control must work"
run "$ours" probe || fail "the output does not pass the probe"
run "$control" probe || fail "the control does not pass the probe, so it cannot show anything"

echo "--- Planting"
# A GnuTLS configuration that turns every TLS version off: any handshake by a
# library that reads it fails.
for file in /d/M/msys64/ucrt64/etc/gnutls/config /c/etc/gnutls/config "$drive/etc/gnutls/config"; do
    plant "$file" "[overrides]" "disabled-version = tls1.0" "disabled-version = tls1.1" \
        "disabled-version = tls1.2" "disabled-version = tls1.3"
done
# PKCS#11 module lists, in GnuTLS's old format and in p11-kit's, naming the marker.
for file in /c/etc/gnutls/pkcs11.conf "$drive/etc/gnutls/pkcs11.conf"; do
    plant "$file" "load=$(cygpath -m "$marker")"
done
for dir in "$probe/target/etc/pkcs11" "$(cygpath -u "$USERPROFILE")/.config/pkcs11" \
    /c/ucrt64/etc/pkcs11 "$drive/ucrt64/etc/pkcs11"; do
    plant "$dir/pkcs11.conf" "user-config: merge"
    plant "$dir/modules/planted.module" "module: $(cygpath -m "$marker")"
done
rm -f "$marker.loaded"

echo "--- The output must ignore all of it"
run "$ours" probe || fail "the output's probe fails with the planted files in place"
grep -qx 'RESULT: PASS' run.txt || fail "the output's probe did not pass"
run "$ours" connect testuser testpass || fail "the output's connect fails with the planted files in place"
grep -qx 'RESULT: PASS' run.txt || fail "the output's connect did not pass"
[ ! -e "$marker.loaded" ] || fail "the output loaded the planted PKCS#11 module"
echo "probe and connect pass; the planted module was not loaded"

echo "--- The control must be broken by it"
if run "$control" probe; then
    fail "the control still passes, so the planted files are not where a library reads them"
fi
grep -q 'No or insufficient priorities were set' run.txt ||
    fail "the control failed, but not because of the planted GnuTLS configuration"
echo "the control fails: $(grep 'SSL connection failure' run.txt | head -1)"
if [ -e "$marker.loaded" ]; then
    echo "the control also loaded the planted PKCS#11 module"
else
    echo "the control did not load the planted PKCS#11 module"
fi
