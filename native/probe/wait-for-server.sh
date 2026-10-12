#!/usr/bin/env bash
# Waits until a test server started in the background accepts connections on a
# local port. Used by the native build workflows on all three systems.
# Usage: wait-for-server.sh <port> <process id of the server>
#
# It gives up 30 seconds after it starts, plus at most one more attempt. An
# attempt on a closed port returns at once on Linux and macOS and takes about
# two seconds on Windows, so the tries are timed rather than counted.
#
# It fails at once if the server has exited. It also fails if the port answers
# but the server is no longer running: then something else holds the port, and
# the test would be talking to that instead.
set -euo pipefail

port=$1
server=$2

# kill -0 cannot signal a server started with sudo; ps can still see it.
running() {
    kill -0 "$server" 2>/dev/null || ps -p "$server" >/dev/null 2>&1
}

SECONDS=0
while [ "$SECONDS" -lt 30 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        if ! running; then
            echo "error: port $port answers, but the server (process $server) has exited: something else is using the port" >&2
            exit 1
        fi
        exit 0
    fi
    if ! running; then
        echo "error: the server (process $server) exited before it listened on port $port" >&2
        exit 1
    fi
    sleep 0.5
done
echo "error: the server (process $server) is running but nothing listens on port $port after 30 seconds" >&2
exit 1
