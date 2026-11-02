#!/usr/bin/env bash
# Checks that the ar, tar and xz which fpm writes the Linux .deb with are
# the pinned ones: each is found first on PATH in /usr/bin and comes from a
# package that native/linux/test-packages.sh installed at its pin, and fpm
# finds no other tar (gtar). The installer workflow runs it with the PATH
# that `pnpm package:linux` gives fpm, just before it packages.
#
# Usage: check-tools.sh <package>...
#   the packaging tools as given to test-packages.sh, which has just
#   checked that each is installed at the version pinned there.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }
[ $# -ge 1 ] || fail "usage: check-tools.sh <package>..."
declare -A pinned=()
for package in "$@"; do
    pinned[$package]=1
done

for tool in ar tar xz; do
    path=$(command -v "$tool") || fail "$tool is not on PATH"
    [ "$path" = "/usr/bin/$tool" ] || fail "$tool is found first at $path, not /usr/bin/$tool"
    real=$(readlink -f "$path")
    # dpkg may record the file under /bin, which /usr/bin is merged with.
    owner=$(dpkg-query -S "$real" 2>/dev/null || dpkg-query -S "${real#/usr}" 2>/dev/null) ||
        fail "no package owns $real"
    owner=${owner%%:*}
    [ -n "${pinned[$owner]:-}" ] || fail "$tool ($real) comes from $owner, which is not a pinned packaging tool"
    echo "$tool: $path -> $real, from $owner $(dpkg-query -W -f '${Version}' "$owner"): $("$tool" --version | sed -n 1p)"
done
! command -v gtar > /dev/null || fail "gtar is on PATH at $(command -v gtar); fpm would use it instead of tar"
echo "fpm will write the .deb with the pinned ar, tar and xz"
