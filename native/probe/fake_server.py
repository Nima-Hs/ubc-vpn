"""Minimal fake AnyConnect gateway for the spike.

POST /      -> login form
POST /auth  -> success plus a session cookie
CONNECT     -> CSTP headers (address, split-include routes), then holds the socket open
"""
import http.server
import ssl
import sys
import time

FORM = b"""<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<version who="sg">0.1(1)</version>
<auth id="main">
<message>Please enter your username and password.</message>
<form method="post" action="/auth">
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
</form></auth>
</config-auth>
"""

SUCCESS = b"""<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">0.1(1)</version>
<auth id="success">
<title>SSL VPN Service</title></auth></config-auth>
"""

CSTP = [
    ("X-CSTP-Version", "1"),
    ("X-CSTP-Server-Name", "Spike fake gateway"),
    ("X-CSTP-DPD", "60"),
    ("X-CSTP-Default-Domain", "example.test"),
    ("X-CSTP-Address", "10.99.0.121"),
    ("X-CSTP-Netmask", "255.255.255.0"),
    ("X-CSTP-DNS", "10.99.0.1"),
    ("X-CSTP-Split-Include", "10.50.0.0/255.255.0.0"),
    ("X-CSTP-Split-Include", "192.168.77.0/255.255.255.0"),
    ("X-CSTP-Keepalive", "300"),
    ("X-CSTP-Base-MTU", "1500"),
    ("X-CSTP-MTU", "1400"),
]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _xml(self, body, cookies=()):
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Transcend-Version", "1")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.startswith("/auth"):
            self._xml(SUCCESS, ["webvpn=spike-fake-cookie; Secure; HttpOnly"])
        else:
            self._xml(FORM)

    do_GET = do_POST

    def do_CONNECT(self):
        self.send_response(200, "CONNECTED")
        for k, v in CSTP:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.flush()
        time.sleep(60)
        self.close_connection = True


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[3])), Handler)
srv.daemon_threads = True
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
