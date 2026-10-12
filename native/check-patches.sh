#!/usr/bin/env bash
# The three native builds each keep a copy of the patch that stops
# libopenconnect closing file descriptor 0. Fails unless the copies are the
# same file, byte for byte. Each native workflow runs this, so a change to one
# copy alone cannot pass.
# Usage: check-patches.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
first=$here/windows/patches/openconnect/0002-init-cmd-fd-write.patch
for other in macos linux; do
    cmp "$first" "$here/$other/patches/openconnect/0001-init-cmd-fd-write.patch"
done
echo "The three copies of init-cmd-fd-write.patch are identical."
