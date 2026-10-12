#!/usr/bin/env bash
# Records, with Process Monitor, every file and registry key touched by the
# probe and by any process it starts, while it runs against the build output.
#
#   Files must be in the probe's own folder, or under C:\Windows in a place
#   ordinary users cannot write. Anything else needs a rule in trace-allow.txt.
#   Registry keys must each match a rule in trace-allow.txt.
#
# The probe and the DLLs are copied into one folder first, the way an installed
# program has them, so that Windows does not go looking for DLLs elsewhere.
#
# Run from Git Bash as an administrator, after the probe has been built, a
# certificate made and wintun.dll put beside the probe (see ../probe).
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
probe=$here/../probe
stage=$here/work/stage
tools=$here/work/procmon

die() {
    echo "error: $*" >&2
    exit 1
}

rm -rf "$stage" "$tools"
mkdir -p "$stage" "$tools"
cp "$here"/out/bin/*.dll "$probe/target/release/oc-probe.exe" "$probe/target/release/wintun.dll" "$stage/"

# Process Monitor has no versioned download, so it cannot be pinned by hash.
# Fetch the program itself, not an archive, and require Microsoft's signature
# on it before it is run. It is a test tool and is not shipped.
procmon=$tools/Procmon64.exe
curl -fsSLo "$procmon" https://live.sysinternals.com/Procmon64.exe
powershell -NoProfile -Command "
    \$s = Get-AuthenticodeSignature -LiteralPath '$(cygpath -w "$procmon")'
    if (\$s.Status -ne 'Valid') { exit 1 }
    if (\$s.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation, O=Microsoft Corporation, ') { exit 1 }
    Write-Host ('Process Monitor ' + (Get-Item -LiteralPath '$(cygpath -w "$procmon")').VersionInfo.FileVersion + ', signed by: ' + \$s.SignerCertificate.Subject)
" || die "Procmon64.exe does not carry a valid Microsoft signature"

cd "$probe"
python fake_server.py cert.pem key.pem 4458 >/dev/null 2>&1 &
"$here/tests/wait-for-server.sh" 4458 $!
python fake_server.py cert.pem key.pem 4459 >/dev/null 2>&1 &
"$here/tests/wait-for-server.sh" 4459 $!

"$procmon" //AcceptEula //Quiet //Minimized //BackingFile "$(cygpath -w "$tools/trace.pml")" &
tracer=$!
"$procmon" //AcceptEula //WaitForIdle
windows=/c/Windows/System32:/c/Windows
(
    cd "$stage"
    PATH="$windows" ./oc-probe.exe probe https://127.0.0.1:4458 | tail -1
    PATH="$windows" ./oc-probe.exe connect https://127.0.0.1:4459 testuser testpass | tail -1
) >"$tools/results.txt"
"$procmon" //AcceptEula //Terminate
wait "$tracer" || true
"$procmon" //AcceptEula //OpenLog "$(cygpath -w "$tools/trace.pml")" //SaveAs "$(cygpath -w "$tools/trace.csv")"

cat "$tools/results.txt"
[ "$(grep -cx 'RESULT: PASS' "$tools/results.txt")" = 2 ] || die "the traced runs did not both pass"
[ -s "$tools/trace.csv" ] || die "Process Monitor saved no trace"

# Columns: time, process, PID, operation, path, result, detail. Follow the
# probe's processes and everything they start ("Process Create" names the new
# PID in its detail), and keep what those processes touched.
awk -F'","' '
    NR == FNR {
        if ($2 == "oc-probe.exe") tree[$3] = 1
        if (($3 in tree) && $4 == "Process Create" && match($0, /PID: [0-9]+/))
            tree[substr($0, RSTART + 5, RLENGTH - 5)] = 1
        next
    }
    ($3 in tree) && $5 != "" { print $2 "\t" $5 }' "$tools/trace.csv" "$tools/trace.csv" | sort -u >"$tools/touched.txt"

echo "Processes traced: $(cut -f1 "$tools/touched.txt" | sort -u | tr '\n' ' ')"
cut -f2 "$tools/touched.txt" | grep -E '^([A-Za-z]:|\\\\)' | sort -u >"$tools/files.txt" || true
cut -f2 "$tools/touched.txt" | grep -E '^HK' | sort -u >"$tools/registry.txt" || true
# A capture that shows neither the DLLs being loaded nor any registry access
# did not work, and must not pass for having found nothing.
grep -q -i -F 'stage\libgnutls-30.dll' "$tools/files.txt" || die "the trace does not show the DLLs being loaded"
[ -s "$tools/registry.txt" ] || die "the trace shows no registry access"

rules() {
    grep -v '^#' "$here/tests/trace-allow.txt" | grep . || true
}
unexplained() {
    grep -v -i -E -f <(rules) || true
}
# The rules must still refuse what they are there to catch.
refused=$(printf '%s\n' 'C:\Temp\evil.dll' 'D:\$Extend\evil.dll' 'HKCU\Software\GnuTLS' | unexplained | wc -l)
[ "$refused" -eq 3 ] || die "trace-allow.txt lets through a path it must refuse"
echo "Self-test: trace-allow.txt refuses all 3 paths it must refuse."

# --- Files -------------------------------------------------------------------

stage_win=$(cygpath -w "$stage")
STAGE=$stage_win awk '
    BEGIN { stage = tolower(ENVIRON["STAGE"]) "\\" }
    index(tolower($0) "\\", stage) != 1' "$tools/files.txt" >"$tools/outside.txt"
grep -i -E '^C:\\Windows(\\|$)' "$tools/outside.txt" >"$tools/in-windows.txt" || true
grep -v -i -E '^C:\\Windows(\\|$)' "$tools/outside.txt" >"$tools/elsewhere.txt" || true

# Which of the paths under C:\Windows could an ordinary user create or change?
# user-writable.ps1 reads the permissions. Check first that it can tell.
user_writable() {
    powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "$here/tests/user-writable.ps1")" \
        "$(cygpath -w "$1")" | tr -d '\r'
}
printf '%s\n' 'C:\Windows\Temp\not-there.txt' 'C:\Windows\System32\not-there.txt' >"$tools/known.txt"
[ "$(user_writable "$tools/known.txt")" = 'C:\Windows\Temp\not-there.txt' ] ||
    die "the permission check does not tell C:\\Windows\\Temp from C:\\Windows\\System32"
echo "Self-test: the permission check reports C:\\Windows\\Temp and not C:\\Windows\\System32."
user_writable "$tools/in-windows.txt" >"$tools/writable.txt"

echo "Files: $(wc -l <"$tools/files.txt") touched, $(wc -l <"$tools/in-windows.txt") of them under C:\\Windows."
echo "::group::Files outside $stage_win and C:\\Windows"
cat "$tools/elsewhere.txt"
echo "::endgroup::"
echo "::group::Files under C:\\Windows where ordinary users can write"
cat "$tools/writable.txt"
echo "::endgroup::"
bad_files=$(cat "$tools/elsewhere.txt" "$tools/writable.txt" | unexplained)

# --- Registry ----------------------------------------------------------------

echo "Registry: $(wc -l <"$tools/registry.txt") keys and values touched."
echo "::group::Registry, by the first four parts of the key"
cut -d'\' -f1-4 "$tools/registry.txt" | sort | uniq -c
echo "::endgroup::"
bad_keys=$(unexplained <"$tools/registry.txt")
# The rules cover Windows' own keys by subtree. A key that names one of our
# libraries would be configuration of ours, and no rule should let it through.
! grep -i -E 'gnutls|openconnect|nettle|libxml|iconv|zlib|p11|pkcs' "$tools/registry.txt" ||
    die "the probe read a registry key that names one of the bundled libraries"

if [ -n "$bad_files$bad_keys" ]; then
    echo "error: not covered by tests/trace-allow.txt:" >&2
    printf '%s\n' "$bad_files" "$bad_keys" | grep . | head -200 >&2
    exit 1
fi
echo "all files and registry keys are covered by tests/trace-allow.txt"
