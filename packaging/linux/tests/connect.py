"""Answers `ubc-vpn connect --json` for packaging/linux/tests/systemd.sh.

The answers are the made-up account of the test gateway that systemd.sh
starts, given on standard input as the app gives them, never as arguments.
Prints each line the client writes, apart from what it was asked, which is
shown by kind and label only.

Usage: python3 -I connect.py <client>
The client runs with this program's environment.
Exits 0 when the client ended with "done".
"""

import json
import subprocess
import sys

# Made up, as in systemd.sh.
ANSWERS = {"username": "someone", "password": "not-a-real-password"}


def main() -> int:
    client = subprocess.Popen(
        [sys.argv[1], "connect", "--json"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert client.stdin is not None and client.stdout is not None
    last = {}
    for line in iter(client.stdout.readline, ""):
        message = json.loads(line)
        if message.get("type") == "prompt":
            kind = message.get("kind")
            print(f"asked: {kind} ({message.get('label')})", flush=True)
            value = ANSWERS.get(kind)
            reply = (
                {"type": "cancel"}
                if value is None
                else {"type": "answer", "id": message["id"], "value": value}
            )
            client.stdin.write(json.dumps(reply) + "\n")
            client.stdin.flush()
            continue
        print(line.strip(), flush=True)
        last = message
        if message.get("type") in ("done", "error"):
            break
    client.stdin.close()
    status = client.wait(timeout=60)
    return 0 if status == 0 and last.get("type") == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
