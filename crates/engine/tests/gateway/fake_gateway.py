"""A stand-in AnyConnect gateway for the engine's login tests.

It listens on this machine only and is not a VPN server. Never give it real
credentials: it writes every request it receives, body included, to a file.

Usage: fake_gateway.py <cert.pem> <key.pem> <scenario> <request log>

It prints "PORTS <main> <other>" and serves until it is killed. The other
port is a second listener that a scenario may try to send the client to; a
correct client never talks to it. Each request is one JSON line in the log.

Scenarios, by what the gateway does after showing the login form:
  accept    takes the answers and returns a session cookie
  reject    shows the form again with an error, every time
  code      asks for a one-time code on a second form, then accepts
  group     shows a form with a choice of group
  hang      never answers the login, for cancelling
  redirect  answers the first request with a redirect to the other port
  action    shows a form whose action is a URL on the other port
  csd       offers a host-scan program to download and run
  fields    shows a form that also has a hidden field and one to ignore
  codeagain asks for a one-time code, and asks again after every code
  otherhost answers the first request with a redirect to another host name
            on the same port (443)
  otherport answers the first request with a redirect to the same host name
            on another port (8443)
  csdstub   offers a host-scan program whose stub is on the gateway's own
            host, so that a client fetches it before refusing to run it.
            Unpatched libopenconnect 9.21 crashes on it on macOS and Linux,
            when the login address has no path; no test uses it yet
  sso       shows a single sign-on form for an external browser, whose
            login page is on the other listener

Never run a client against "sso" that may have the external-browser login:
such a client starts a browser on the machine it runs on.

The two redirect scenarios redirect to places a client must not go, each wrong in one way
only. In a test the client's resolver decides where those names lead.

A tunnel: in every scenario, a CONNECT that carries the session cookie gets
the addresses below (TUNNEL) and the connection is then held open, without
passing any traffic, until the client closes it. A CONNECT without that
cookie is refused with 401, as a gateway refuses a session that has ended.
In the scenario "ended" every CONNECT is refused so.

It stops when its standard input closes, which is when the test that started
it ends, however that test ends. Started by hand with no input, it stops at
once: give it a terminal, or a pipe that stays open.
"""

import http.server
import json
import os
import ssl
import sys
import threading
import time

COOKIE = "webvpn=FAKE-GATEWAY-COOKIE-0123456789abcdef"
SCENARIOS = (
    "accept", "reject", "code", "group", "hang", "redirect", "action", "csd", "fields",
    "codeagain", "otherhost", "otherport", "sso", "csdstub", "ended",
)
# What a tunnel is given. Made-up, private addresses only.
TUNNEL = (
    ("X-CSTP-Version", "1"),
    ("X-CSTP-Address", "10.11.12.13"),
    ("X-CSTP-Netmask", "255.255.255.0"),
    ("X-CSTP-DNS", "10.11.0.1"),
    ("X-CSTP-DNS", "10.11.0.2"),
    ("X-CSTP-MTU", "1300"),
    ("X-CSTP-Split-Include", "10.0.0.0/255.0.0.0"),
    ("X-CSTP-Split-Include", "192.0.2.0/255.255.255.0"),
    ("X-CSTP-Keepalive", "20"),
    ("X-CSTP-DPD", "30"),
    ("X-CSTP-Idle-Timeout", "1800"),
)


def sso_form(elsewhere):
    """A form that asks the client to log in by single sign-on in an
    external browser, the way the library reads one."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<config-auth client="vpn" type="auth-request">'
        '<version who="sg">0.1(1)</version>'
        '<auth id="main"><message>Log in with your browser.</message>'
        "<sso-v2-login>%s/sso</sso-v2-login>"
        "<sso-v2-login-final>%s/sso/done</sso-v2-login-final>"
        "<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>"
        "<sso-v2-error-cookie-name>acSamlv2Error</sso-v2-error-cookie-name>"
        "<sso-v2-browser-mode>external</sso-v2-browser-mode>"
        '<form method="post" action="/auth">'
        '<input type="sso" name="sso-token" label="" /></form></auth>'
        "</config-auth>" % (elsewhere, elsewhere)
    ).encode()


def form(action, fields, message="Please log in.", error=None, extra=""):
    inputs = "".join(
        '<input type="%s" name="%s" label="%s" />' % field for field in fields
    )
    error = "<error>%s</error>" % error if error else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<config-auth client="vpn" type="auth-request">'
        '<version who="sg">0.1(1)</version>%s'
        '<auth id="main"><message>%s</message>%s'
        '<form method="post" action="%s">%s</form></auth>'
        "</config-auth>" % (extra, message, error, action, inputs)
    ).encode()


LOGIN = (("text", "username", "Username:"), ("password", "password", "Password:"))
CODE = (("password", "secondary_password", "Code:"),)
GROUP = (
    '<select name="group_list" label="Group:">'
    '<option selected="true">Staff</option><option>Students</option></select>'
)
# A field the library is to ignore, because the group chosen by default has no
# second login, and a hidden one. A field can only be ignored on a form with
# a choice of group.
EXTRA = (
    '<input type="password" name="secondary_password" label="Second:" second-auth="1" />'
    '<input type="hidden" name="token" value="FAKE-HIDDEN-VALUE" />' + GROUP
)
SUCCESS = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<config-auth client="vpn" type="complete">'
    b'<version who="sg">0.1(1)</version>'
    b'<auth id="success"><title>Fake gateway</title></auth></config-auth>'
)


def host_scan(base):
    return (
        "<host-scan><host-scan-ticket>FAKE-TICKET</host-scan-ticket>"
        "<host-scan-token>FAKE-TOKEN</host-scan-token>"
        "<host-scan-base-uri>%s/CACHE/sdesktop</host-scan-base-uri>"
        "<host-scan-wait-uri>/+CSCOE+/sdesktop/wait.html</host-scan-wait-uri>"
        "</host-scan>" % base
    )


class Gateway(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    scenario = "accept"
    listener = "main"
    other_port = 0
    log_path = ""
    log_lock = threading.Lock()
    context = None

    def setup(self):
        # The TLS handshake happens here, on this connection's own thread,
        # and not where connections are accepted: a client that connects and
        # then says nothing holds up only itself, and only for ten seconds.
        self.request.settimeout(10)
        self.request = self.context.wrap_socket(self.request, server_side=True)
        self.request.settimeout(None)
        super().setup()

    def log_message(self, *_):
        pass

    def record(self, body):
        entry = {
            "listener": self.listener,
            "method": self.command,
            "path": self.path,
            "body": body.decode("utf-8", "replace"),
        }
        with self.log_lock, open(self.log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps(entry) + "\n")

    def reply(self, body, cookie=None, status=200, location=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Transcend-Version", "1")
        if cookie:
            self.send_header("Set-Cookie", cookie + "; Secure; HttpOnly")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.record(body)
        scenario, elsewhere = self.scenario, "https://127.0.0.1:%d" % self.other_port
        if self.listener != "main":
            # Whatever reaches the other listener is answered like a gateway
            # that accepts, so that a client that follows is seen to succeed.
            self.reply(SUCCESS, COOKIE)
        elif self.path.startswith("/code"):
            if scenario == "codeagain":
                self.reply(form("/code", CODE, message="Enter the code.", error="Wrong code."))
            else:
                self.reply(SUCCESS, COOKIE)
        elif self.path.startswith("/auth"):
            if scenario == "hang":
                time.sleep(3600)
            elif scenario == "reject":
                self.reply(form("/auth", LOGIN, error="Login failed."))
            elif scenario in ("code", "codeagain"):
                self.reply(form("/code", CODE, message="Enter the code."))
            else:
                self.reply(SUCCESS, COOKIE)
        elif scenario == "redirect":
            self.reply(b"", status=302, location=elsewhere + "/")
        elif scenario == "csdstub" and self.path == "/":
            # The stub to run is on the gateway's own host. Each platform's
            # client reads its own tag; all three are here.
            own = "https://vpn.example.test"
            tags = "".join(
                '<%s stuburl="%s/CACHE/stub" starturl="%s/CACHE/start" '
                'waiturl="/+CSCOE+/sdesktop/wait.html" />' % (tag, own, own)
                for tag in ("csd", "csdLinux", "csdMac")
            )
            body = form("/auth", LOGIN, extra=host_scan(own))
            self.reply(body.replace(b'<auth id="main">', b'<auth id="main">' + tags.encode()))
        elif scenario == "sso":
            self.reply(sso_form(elsewhere))
        elif scenario == "otherhost" and self.path == "/":
            # Wherever the client's resolver sends this name, a correct
            # client does not ask it.
            self.reply(b"", status=302, location="https://other.example.test/again")
        elif scenario == "otherport" and self.path == "/":
            self.reply(b"", status=302, location="https://vpn.example.test:8443/again")
        elif scenario == "action":
            self.reply(form(elsewhere + "/auth", LOGIN))
        elif scenario == "group":
            self.reply(form("/auth", LOGIN).replace(b"</form>", GROUP.encode() + b"</form>"))
        elif scenario == "csd":
            self.reply(form("/auth", LOGIN, extra=host_scan(elsewhere)))
        elif scenario == "fields":
            self.reply(form("/auth", LOGIN).replace(b"</form>", EXTRA.encode() + b"</form>"))
        else:
            self.reply(form("/auth", LOGIN))

    do_GET = do_POST

    def do_CONNECT(self):
        cookies = self.headers.get_all("Cookie") or []
        has_cookie = any(COOKIE in cookie for cookie in cookies)
        # Logged as whether the cookie came, not the cookie itself.
        self.record(b"cookie" if has_cookie else b"no cookie")
        if self.listener != "main" or not has_cookie or self.scenario == "ended":
            self.send_response(401, "Unauthorized")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.close_connection = True
            return
        self.send_response(200, "CONNECTED")
        for name, value in TUNNEL:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.flush()
        # Hold the tunnel open and drop what the client sends, until it
        # closes the connection.
        try:
            while self.rfile.read1(4096):
                pass
        except OSError:
            pass
        self.close_connection = True


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # A client that gives up during the handshake, as one does when the
        # key is not the one it pins, is not worth a traceback.
        pass


def listen(listener, context):
    handler = type("Handler", (Gateway,), {"listener": listener, "context": context})
    return Server(("127.0.0.1", 0), handler)


def main(cert, key, scenario, log_path):
    if scenario not in SCENARIOS:
        sys.exit("unknown scenario: " + scenario)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    Gateway.scenario, Gateway.log_path = scenario, log_path
    open(log_path, "w", encoding="utf-8").close()
    servers = [listen("main", context), listen("other", context)]
    Gateway.other_port = servers[1].server_address[1]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("PORTS %d %d" % tuple(s.server_address[1] for s in servers), flush=True)
    # Whoever started this holds the other end of standard input. When they
    # are gone, however they went, so is this.
    sys.stdin.buffer.read()
    os._exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
