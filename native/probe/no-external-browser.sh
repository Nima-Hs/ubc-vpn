#!/usr/bin/env bash
# Fails if a built libopenconnect contains the external-browser login: the
# code that listens on local port 29786 for a browser, and the offer of that
# login to the gateway. Both exist only in a build with HPKE, which ours turn
# off. Looks for their messages in the file itself, so it checks what ships.
# Usage: no-external-browser.sh <libopenconnect file>
set -euo pipefail

lib=$1
[ -f "$lib" ] || { echo "error: no such file: $lib" >&2; exit 1; }
found=0
for text in 'local port 29786' 'single-sign-on-external-browser'; do
    if grep -aqF "$text" "$lib"; then
        echo "error: $lib contains \"$text\"" >&2
        found=1
    fi
done
[ "$found" = 0 ]
echo "$lib has no external-browser login."
