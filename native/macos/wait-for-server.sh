#!/usr/bin/env bash
# Waits for the stand-in gateway (../probe/fake_server.py) to accept
# connections, for up to 30 seconds. Fails at once if the server has exited.
# Usage: wait-for-server.sh <port> <process id of the server>
set -euo pipefail

port=$1
server=$2

for _ in $(seq 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        exit 0
    fi
    if ! kill -0 "$server" 2>/dev/null; then
        echo "error: the stand-in server (process $server) exited before it listened on port $port" >&2
        exit 1
    fi
    sleep 0.5
done
echo "error: the stand-in server is running but nothing listens on port $port after 30 seconds" >&2
exit 1
