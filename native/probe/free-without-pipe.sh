#!/usr/bin/env bash
# Builds free_without_pipe.c against a built libopenconnect and runs it. Fails
# unless the library leaves file descriptor 0 open when it frees a handle that
# never made a command pipe, which shows the build carries our patch for it.
# Usage: free-without-pipe.sh <folder with include/ and lib/>
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
stage=$(cd "$1" && pwd)
work=$(mktemp -d)

cc -Wall -Wextra -Werror "$here/free_without_pipe.c" \
    -I"$stage/include" -L"$stage/lib" -lopenconnect -Wl,-rpath,"$stage/lib" \
    -o "$work/free_without_pipe"
"$work/free_without_pipe" < /dev/null
