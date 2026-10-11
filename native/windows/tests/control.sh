#!/usr/bin/env bash
# Prepares the control for planted-files.sh in work/control/bin: the build
# output, with our GnuTLS swapped for MSYS2's stock one and the DLLs that one
# needs. The stock library is known to read planted files, so it shows that
# the test can fail. Run in an MSYS2 UCRT64 shell, after build.sh.
set -euo pipefail
. "$(dirname "$0")/../common.sh"
require_ucrt64

control=$work/control
rm -rf "$control"
mkdir -p "$control/stock" "$control/bin"

# The stock packages are unpacked here, never installed.
while read -r _ file; do
    tar -xf "$here/cache/packages/$file" -C "$control/stock" ucrt64/bin
done <"$here/control.lock"

cp "$out"/bin/*.dll "$control/bin/"
cp "$control/stock/ucrt64/bin/libgnutls-30.dll" "$control/bin/"
collect_dlls "$control/bin" libgnutls-30.dll "$control/stock/ucrt64/bin" "$PREFIX/bin"
