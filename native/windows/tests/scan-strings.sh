#!/usr/bin/env bash
# Looks in every shipped DLL for text that could be a file path the library
# opens: absolute paths, and the words that marked the unsafe paths found in
# MSYS2's GnuTLS. Each hit must match a rule in strings-allow.txt, where it has
# been examined and given a reason. Run in an MSYS2 UCRT64 shell, after build.sh.
set -euo pipefail
. "$(dirname "$0")/../common.sh"
require_ucrt64

pattern='(^|[^A-Za-z0-9])[A-Za-z]:[\\/]|ucrt64|msys64|/etc/|\\etc\\|pkcs11'

mkdir -p "$work"
for dll in "$out"/bin/*.dll; do
    # Plain text, then UTF-16, which is how Windows programs often store paths.
    # Six characters is the shortest path worth finding, such as C:\etc.
    { strings -a -n 6 "$dll" && strings -a -n 6 -e l "$dll"; } |
        grep -i -E "$pattern" | sort -u | sed "s|^|${dll##*/} |" || true
done >"$work/string-hits.txt"

# A rule is "<dll> <regular expression>"; a hit is "<dll> <text>".
unexplained=$(awk '
    BEGIN { n = 0 }
    NR == FNR { if ($0 !~ /^#/ && NF) { dll[n] = $1; sub(/^[^ ]+ +/, ""); rule[n++] = $0 }; next }
    {
        text = $0; sub(/^[^ ]+ /, "", text)
        for (i = 0; i < n; i++) if (dll[i] == $1 && text ~ ("^(" rule[i] ")$")) next
        print
    }' "$here/tests/strings-allow.txt" "$work/string-hits.txt")

echo "::group::Path-like strings, as <dll> <text>"
cat "$work/string-hits.txt"
echo "::endgroup::"
echo "$(wc -l <"$work/string-hits.txt") path-like strings found in $(find "$out/bin" -name '*.dll' | wc -l) DLLs"
[ -z "$unexplained" ] || die "not covered by tests/strings-allow.txt:"$'\n'"$unexplained"
echo "all are covered by tests/strings-allow.txt"
