#!/usr/bin/env bash
# Waits up to 30 seconds for a TCP port on localhost to accept connections.
# Usage: wait-for-port.sh <port>
set -euo pipefail

for _ in $(seq 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
        exit 0
    fi
    sleep 1
done
echo "error: nothing is listening on port $1" >&2
exit 1
