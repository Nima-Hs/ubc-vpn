#!/usr/bin/env bash
# Looks in every shipped DLL for text that could be a file the library opens
# or an environment variable it obeys. Each hit must match a rule in
# strings-allow.txt, where it has been examined and given a reason.
# Run in an MSYS2 UCRT64 shell, after build.sh.
set -euo pipefail
. "$(dirname "$0")/../common.sh"
require_ucrt64

# Paths: absolute ones, the words that marked the unsafe paths found in MSYS2's
# GnuTLS, and GnuTLS's per-user folder. Matched without regard to case.
paths='(^|[^A-Za-z0-9])[A-Za-z]:[\\/]|ucrt64|msys64|/etc/|\\etc\\|pkcs11|\.gnutls'
# Environment variables: whole strings that look like a variable's name. The
# names end the way such names do, or are the ones Windows and Unix programs
# use to find a home or temporary folder. Matched exactly.
variables='^[A-Za-z][A-Za-z0-9_]*(FILE|FILES|LEVEL|DIR|PATH|OVERRIDE|VERBOSE|RECLAIM|KEYLOG|DEBUG|INIT|MODE|PROXY|_proxy|CATALOG)$'
variables+='|^(HOME|HOMEDRIVE|HOMEPATH|USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|TMPDIR|SSLKEYLOGFILE)$'

mkdir -p "$work"
for dll in "$out"/bin/*.dll; do
    # Plain text, then UTF-16, which is how Windows programs often store paths.
    # Six characters is the shortest path worth finding, such as C:\etc; a
    # variable's name can be as short as TMP.
    {
        { strings -a -n 6 "$dll" && strings -a -n 6 -e l "$dll"; } | grep -i -E "$paths" || true
        { strings -a -n 3 "$dll" && strings -a -n 3 -e l "$dll"; } | grep -E "$variables" || true
    } | sort -u | sed "s|^|${dll##*/} |"
done >"$work/string-hits.txt"

echo "::group::Strings found, as <dll> <text>"
cat "$work/string-hits.txt"
echo "::endgroup::"

# The variable the GnuTLS patch removes must be gone, not merely allowed.
! grep -q 'GNUTLS_SYSTEM_PRIORITY' "$work/string-hits.txt" ||
    die "a DLL still mentions GNUTLS_SYSTEM_PRIORITY_FILE"
! grep -a -q 'GNUTLS_SYSTEM_PRIORITY' "$out/bin/libgnutls-30.dll" ||
    die "libgnutls-30.dll still mentions GNUTLS_SYSTEM_PRIORITY_FILE"

# A rule is "<dll> <regular expression>"; a hit is "<dll> <text>".
unexplained=$(awk '
    BEGIN { n = 0 }
    NR == FNR { if ($0 !~ /^#/ && NF) { dll[n] = $1; sub(/^[^ ]+ +/, ""); rule[n++] = $0 }; next }
    {
        text = $0; sub(/^[^ ]+ /, "", text)
        for (i = 0; i < n; i++) if (dll[i] == $1 && text ~ ("^(" rule[i] ")$")) next
        print
    }' "$here/tests/strings-allow.txt" "$work/string-hits.txt")

echo "$(wc -l <"$work/string-hits.txt") strings found in $(find "$out/bin" -name '*.dll' | wc -l) DLLs"
[ -z "$unexplained" ] || die "not covered by tests/strings-allow.txt:"$'\n'"$unexplained"
echo "all are covered by tests/strings-allow.txt"
