#!/usr/bin/env bash
# Records every file the probe opens while it runs against the build output,
# using Process Monitor, and fails if one is outside the folder the DLLs were
# loaded from and outside Windows, unless trace-allow.txt explains it.
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

rm -rf "$stage" "$tools"
mkdir -p "$stage" "$tools"
cp "$here"/out/bin/*.dll "$probe/target/release/oc-probe.exe" "$probe/target/release/wintun.dll" "$stage/"

# Process Monitor has no versioned download, so it cannot be pinned by hash.
# Require Microsoft's signature instead. It is a test tool and is not shipped.
curl -fsSLo "$tools/procmon.zip" https://download.sysinternals.com/files/ProcessMonitor.zip
unzip -q "$tools/procmon.zip" -d "$tools"
procmon=$tools/Procmon64.exe
powershell -NoProfile -Command "
    \$s = Get-AuthenticodeSignature '$(cygpath -w "$procmon")'
    if (\$s.Status -ne 'Valid' -or \$s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { exit 1 }
    Write-Host ('Process Monitor ' + (Get-Item '$(cygpath -w "$procmon")').VersionInfo.FileVersion + ', signed by Microsoft')
" || { echo "error: Procmon64.exe is not signed by Microsoft" >&2; exit 1; }

cd "$probe"
python fake_server.py cert.pem key.pem 4458 >/dev/null 2>&1 &
python fake_server.py cert.pem key.pem 4459 >/dev/null 2>&1 &
sleep 3

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
[ "$(grep -cx 'RESULT: PASS' "$tools/results.txt")" = 2 ] || { echo "error: the traced runs did not both pass" >&2; exit 1; }

# Columns: time, process, PID, operation, path, result, detail. Keep the paths
# on a drive or a network share that the probe touched.
grep -a '"oc-probe.exe"' "$tools/trace.csv" | awk -F'","' '$5 ~ /^([A-Za-z]:|\\\\)/ { print $5 }' | sort -u >"$tools/paths.txt"
[ -s "$tools/paths.txt" ] || { echo "error: the trace recorded nothing for the probe" >&2; exit 1; }
# The DLLs it loaded must be there, or the trace is not showing file access.
grep -q -i -F 'stage\libgnutls-30.dll' "$tools/paths.txt" || { echo "error: the trace does not show the DLLs being loaded" >&2; exit 1; }

stage_win=$(cygpath -w "$stage")
outside=$(STAGE=$stage_win awk '
    BEGIN { stage = tolower(ENVIRON["STAGE"]) "\\"; windows = "c:\\windows\\" }
    { p = tolower($0) "\\" }
    index(p, stage) != 1 && index(p, windows) != 1' "$tools/paths.txt")
unexplained=$(grep -v -i -E -f <(grep -v '^#' "$here/tests/trace-allow.txt" | grep .) <<<"$outside" || true)

echo "The probe touched $(wc -l <"$tools/paths.txt") paths. Outside $stage_win and C:\\Windows:"
echo "${outside:-(none)}"
if [ -n "$unexplained" ]; then
    echo "error: not covered by tests/trace-allow.txt:" >&2
    echo "$unexplained" >&2
    exit 1
fi
echo "all are covered by tests/trace-allow.txt"
