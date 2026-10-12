"""A plain TLS client for the tests of the stand-in gateway itself.

Usage: client.py <port> <path> [body]

It posts to https://127.0.0.1:<port><path>, accepting any certificate, and
prints one JSON line: the status, the Location and Set-Cookie headers and
the body, or an error. It talks to this machine only and gives up after two
seconds. The engine's own login tests do not use it; they use the engine.
"""

import http.client
import json
import ssl
import sys


def main(port, path, body=""):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection("127.0.0.1", int(port), context=context, timeout=2)
    try:
        connection.request("POST", path, body)
        reply = connection.getresponse()
        result = {
            "status": reply.status,
            "location": reply.getheader("Location"),
            "cookie": reply.getheader("Set-Cookie"),
            "body": reply.read().decode("utf-8", "replace"),
        }
    except OSError as error:
        result = {"error": type(error).__name__}
    print(json.dumps(result))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    main(*sys.argv[1:])
