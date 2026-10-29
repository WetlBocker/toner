# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# API Tester: building and sending requests, every auth type, variables (secret ones too), the proxy, the verify switch, saved
# requests and folders across organizations, history, masked audit lines, and the page itself.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import base64, http.server, json, os, socket, ssl, sys, threading, time
from datetime import datetime, timedelta, timezone
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\api%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import apitool as A, audit, db, orgs, profiles, proxy
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox
app = QApplication([])
import app as APP
APP.apply_look(app)
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.exec = lambda self: 0                      # question boxes (unsaved changes, delete): no button clicked = "Don't save" / nothing deleted

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def refused(fn, word):
    try: fn(); return False
    except ValueError as e: return word.lower() in str(e).lower()
def db_text():
    """Everything in every database file, to look for secrets in."""
    out = b""
    for org in [db.GLOBAL] + [r["id"] for r in db.org_rows()]:
        p = db.org_path(org)
        if p.exists():
            with db.within(org), db.connect() as c:
                c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            out += open(p, "rb").read()
    return out


# ================================================================ a target that records what it gets
hits = []
class Target(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _take(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        hits.append({"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        return body
    def _reply(self, code, body, ctype="application/json"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Served-By", "fake"); self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
    def _any(self):
        body = self._take()
        if self.path.startswith("/slow"):
            time.sleep(3); return self._reply(200, b"{}")
        if self.path.startswith("/xml"):
            return self._reply(200, b"<root><a x='1'><b>text</b></a></root>", "application/xml")
        if self.path.startswith("/big"):
            return self._reply(200, b"x" * (6 * 1024 * 1024), "text/plain")
        if self.path.startswith("/text"):
            return self._reply(200, "plain é".encode("latin-1"), "text/plain; charset=iso-8859-1")
        if self.path.startswith("/go"):
            self.send_response(302); self.send_header("Location", "/landed"); self.send_header("Content-Length", "0"); self.end_headers(); return
        if self.path.startswith("/teapot"):
            return self._reply(418, b'{"error": "short and stout"}')
        if self.path.startswith("/secure"):
            if self.headers.get("Authorization") != "Bearer tok-123": return self._reply(401, b'{"error": "who?"}')
        self._reply(200, json.dumps({"method": self.command, "path": self.path, "echo": body.decode("utf-8", "replace")}).encode())
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _any
    def log_message(self, *a): pass

class Quiet(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address): pass          # a connection Toner cut short (Cancel) is not news
web = Quiet(("127.0.0.1", 0), Target); threading.Thread(target=web.serve_forever, daemon=True).start()
PORT = web.server_address[1]; BASE = f"http://127.0.0.1:{PORT}"

def make_cert(folder, name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-device")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False).sign(key, hashes.SHA256()))
    cp, kp = os.path.join(folder, name + ".crt"), os.path.join(folder, name + ".key")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp
cp, kp = make_cert(SP, "api-self-signed")
tls = Quiet(("127.0.0.1", 0), Target)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.load_cert_chain(cp, kp); tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=tls.serve_forever, daemon=True).start()
TLS = f"https://127.0.0.1:{tls.server_address[1]}"

class HttpProxy:
    """A CONNECT / plain-forwarding HTTP proxy that logs each request line (from tests/test_proxy.py)."""
    def __init__(self):
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(16); self.port = self.sock.getsockname()[1]; self.log = []
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while True:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self._safe, args=(c,), daemon=True).start()
    def _safe(self, c):
        try: self.handle(c)
        except OSError: pass
    def handle(self, c):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk: return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        first = head.decode("latin-1").split("\r\n")[0]; self.log.append(first)
        if first.startswith("CONNECT"):
            host, port = first.split()[1].rsplit(":", 1)
            up = socket.create_connection((host, int(port)), 5); c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if rest: up.sendall(rest)
            self.pipe(c, up)
        else:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy"); c.close()
    @staticmethod
    def pipe(a, b):
        def one(src, dst):
            try:
                while True:
                    d = src.recv(65536)
                    if not d: break
                    dst.sendall(d)
            except OSError: pass
            finally:
                for s in (src, dst):
                    try: s.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
        threading.Thread(target=one, args=(a, b), daemon=True).start(); one(b, a)

def req(**kw):
    r = A.blank(); r.update(kw); return r
def go(r, secret="", values=None):
    hits.clear()
    p = A.build(r, secret, values if values is not None else {})
    return p, A.send(p)
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "none"})

# ================================================================ methods, params, headers, bodies
print("== methods, params, headers and bodies")
for m in A.METHODS:
    p, res = go(req(method=m, url=BASE + "/m"))
    check(f"{m} reaches the server and the reply is read", not res["error"] and res["status"] == 200 and hits[-1]["method"] == m
          and (res["body"] == b"" if m == "HEAD" else json.loads(res["body"])["method"] == m), res)
p, res = go(req(url=BASE + "/p?fixed=1", params=[[True, "a", "1 2"], [True, "b", "x&y"], [False, "off", "no"], [True, "", "blank"]]))
check("ticked params make the query string (encoded), unticked and nameless ones are left out, the URL's own query is replaced by the table",
      hits[-1]["path"] == "/p?a=1+2&b=x%26y", hits[-1]["path"])
check("the query string of a URL becomes rows for the Params table", A.split_query("http://h/x?a=1&b=2&c=") == [[True, "a", "1"], [True, "b", "2"], [True, "c", ""]] and A.split_query("http://h/x") == [])
check("a URL with no ticked params has no query string", A.with_query("http://h/x?a=1", [[False, "a", "1"]]) == "http://h/x")
check("variables in a query stay readable, not percent-encoded", A.with_query("http://{{host}}/x", [[True, "k", "{{key}}"]]) == "http://{{host}}/x?k={{key}}")
p, res = go(req(url=BASE + "/h", headers=[[True, "X-One", "1"], [True, " X-Two ", "two"], [False, "X-Off", "x"], [True, "", "nothing"]]))
check("ticked headers are sent, unticked and nameless ones are not", hits[-1]["headers"].get("x-one") == "1" and hits[-1]["headers"].get("x-two") == "two" and "x-off" not in hits[-1]["headers"])
for kind, ctype in (("json", "application/json; charset=utf-8"), ("xml", "application/xml; charset=utf-8"), ("form", "application/x-www-form-urlencoded"), ("text", "text/plain; charset=utf-8")):
    p, res = go(req(method="POST", url=BASE + "/b", body='{"a": 1}' if kind == "json" else "a=1&b=2", body_type=kind))
    check(f"a {kind} body is sent with its Content-Type", hits[-1]["headers"].get("content-type") == ctype and hits[-1]["body"] in (b'{"a": 1}', b"a=1&b=2"), hits[-1]["headers"].get("content-type"))
p, res = go(req(method="POST", url=BASE + "/b", body="<a/>", body_type="xml", headers=[[True, "Content-Type", "text/xml"]]))
check("a Content-Type header typed by hand wins over the body type", hits[-1]["headers"].get("content-type") == "text/xml")
p, res = go(req(method="POST", url=BASE + "/b", body="ignored", body_type="none"))
check("body type None sends nothing", hits[-1]["body"] == b"" and "content-type" not in hits[-1]["headers"])
p, res = go(req(method="GET", url=BASE + "/go"))
check("redirects are followed, and the final URL is reported", res["status"] == 200 and res["url"].endswith("/landed") and hits[-1]["path"] == "/landed")
p, res = go(req(url=BASE + "/teapot"))
check("an error status is a reply, not an error", res["status"] == 418 and not res["error"] and A.status_text(res).startswith("418"), A.status_text(res))
check("the status line has the code, reason, time and size", "  ·  " in A.status_text(res) and " ms  ·  " in A.status_text(res) and "bytes" in A.status_text(res), A.status_text(res))
check("reply headers come back as pairs", ("X-Served-By", "fake") in res["headers"])

print("== what is refused before sending")
check("no URL", refused(lambda: A.build(req(url=""), "", {}), "enter a url"))
check("a URL without http", refused(lambda: A.build(req(url="10.0.0.1/api"), "", {}), "must start with http"))
check("a URL with nothing after the scheme", refused(lambda: A.build(req(url="https://"), "", {}), "needs a host"))
check("bearer with no token", refused(lambda: A.build(req(url=BASE, auth={"type": "bearer"}), "", {}), "enter the token"))
check("API key without a name", refused(lambda: A.build(req(url=BASE, auth={"type": "apikey"}), "k", {}), "key name"))
check("a profile not chosen", refused(lambda: A.build(req(url=BASE, auth={"type": "profile"}), "", {}), "choose a profile"))
check("a request needs a name to be saved", refused(lambda: A.save(req(url=BASE)), "give the request a name"))

# ================================================================ auth
print("== auth")
p, res = go(req(url=BASE + "/secure", auth={"type": "bearer"}), "tok-123")
check("a bearer token is sent", res["status"] == 200 and hits[-1]["headers"]["authorization"] == "Bearer tok-123")
p, res = go(req(url=BASE + "/a", auth={"type": "basic", "username": "admin"}), "pa:ss")
check("basic sends user name and password", hits[-1]["headers"]["authorization"] == "Basic " + base64.b64encode(b"admin:pa:ss").decode())
p, res = go(req(url=BASE + "/a", auth={"type": "apikey", "key_name": "X-API-Key", "where": "header"}), "key-9")
check("an API key in a header", hits[-1]["headers"]["x-api-key"] == "key-9")
p, res = go(req(url=BASE + "/a?x=1", auth={"type": "apikey", "key_name": "access_token", "where": "query"}), "k y/z")
check("an API key in a query parameter, encoded, after the other params", hits[-1]["path"] == "/a?x=1&access_token=k%20y%2Fz", hits[-1]["path"])
check("the typed secret is listed for masking, and never a user name", p["secrets"] == ["k y/z"])
check("the audit mask hides it in every form a URL carries it", A.mask("k y/z k%20y%2Fz k%20y/z plain", ["k y/z"]) == "**** **** **** plain")
pid = profiles.save({"name": "fw-api", "username": "apiuser"}, {"main": "prof-secret-77"})
for send_as, where, header, want in (("bearer", "", "authorization", "Bearer prof-secret-77"), ("basic", "", "authorization", "Basic " + base64.b64encode(b"apiuser:prof-secret-77").decode()),
                                     ("header", "", "x-token", "prof-secret-77")):
    r = req(url=BASE + "/a", auth={"type": "profile", "profile_id": pid, "send_as": send_as, "key_name": "X-Token"})
    p, res = go(r)
    check(f"a credential profile sent as {send_as}", hits[-1]["headers"].get(header) == want and "prof-secret-77" in p["secrets"], hits[-1]["headers"])
r = req(url=BASE + "/a", auth={"type": "profile", "profile_id": pid, "send_as": "query", "key_name": "key"})
p, res = go(r); check("a credential profile as a query parameter", hits[-1]["path"] == "/a?key=prof-secret-77")
check("the profile's secret is nowhere in the database", b"prof-secret-77" not in db_text())
empty = profiles.save({"name": "no-secret", "username": "x"})
check("a profile with nothing stored is explained", refused(lambda: A.build(req(url=BASE, auth={"type": "profile", "profile_id": empty}), "", {}), "has no password or token stored"))
check("a profile that is gone is explained", refused(lambda: A.build(req(url=BASE, auth={"type": "profile", "profile_id": 999}), "", {}), "is gone"))

# ================================================================ variables
print("== variables")
A.set_variable("host", f"127.0.0.1:{PORT}")
A.set_variable("path", "things")
A.set_variable("token", "var-secret-55", secret=True)
check("variables are listed by name, a secret one with no value in the list", [(v["name"], v["value"], v["secret"]) for v in A.list_variables()] == [("host", f"127.0.0.1:{PORT}", 0), ("path", "things", 0), ("token", "", 1)])
check("the secret value is in the vault under the organization's name, and not in the database", STORE[("netcheck", "api-var:token")] == "var-secret-55" and b"var-secret-55" not in db_text())
check("values for sending include the secret one", A.variable_values()["token"] == "var-secret-55")
r = req(method="POST", url="http://{{host}}/{{path}}?q={{path}}", params=[[True, "p", "{{ path }}"]], headers=[[True, "X-{{path}}", "{{token}}"]],
        body='{"t": "{{token}}", "p": "{{path}}"}', body_type="json", auth={"type": "apikey", "key_name": "{{path}}-key", "where": "header"})
p, res = go(r, "{{token}}", A.variable_values())
h = hits[-1]
check("{{name}} is filled in the URL, params (spaces inside the braces too), headers, body and auth", h["path"] == "/things?p=things" and h["headers"]["x-things"] == "var-secret-55"
      and json.loads(h["body"]) == {"t": "var-secret-55", "p": "things"} and h["headers"]["things-key"] == "var-secret-55", h)
check("a secret variable's value is listed for masking", "var-secret-55" in p["secrets"])
check("an unresolved variable is refused before sending, naming it", refused(lambda: A.build(req(url="http://{{host}}/{{nope}}"), "", A.variable_values()), "No value for {{nope}}"))
check("unresolved names are found in every field, once each, in order", A.unresolved(req(url="{{a}}{{b}}", headers=[[True, "{{c}}", "{{a}}"]], body="{{d}}", body_type="text", auth={"username": "{{e}}"}), {"b": 1}, "{{f}}") == ["a", "c", "d", "e", "f"])
check("an unticked row's variables do not count", A.unresolved(req(url="x", params=[[False, "{{gone}}", ""]]), {}) == [])
check("a body of type None does not count", A.unresolved(req(url="x", body="{{gone}}", body_type="none"), {}) == [])
check("bad names are refused", refused(lambda: A.set_variable("my host", "x"), "letters, digits") and refused(lambda: A.set_variable("", "x"), "letters, digits"))
check("renaming to a name already used (any case) is refused", refused(lambda: A.set_variable("HOST", "x", old_name="path"), "already a variable named") and A.variable_exists("HOST") and not A.variable_exists("nope"))
A.set_variable("token", "", secret=True)
check("saving a secret variable with a blank value keeps the stored secret", A.variable_values()["token"] == "var-secret-55")
A.set_variable("tok2", "", secret=True, old_name="token")
check("renaming a secret variable moves its value", A.variable_values().get("tok2") == "var-secret-55" and "token" not in A.variable_values() and ("netcheck", "api-var:token") not in STORE)
A.set_variable("tok2", "now-plain", secret=False)
check("making it not secret drops the vault entry and stores the value", ("netcheck", "api-var:tok2") not in STORE and A.variable_values()["tok2"] == "now-plain")
A.delete_variable("tok2"); A.delete_variable("path")
check("deleted", set(A.variable_values()) == {"host"})
A.set_variable("token", "var-secret-55", secret=True)

# ================================================================ proxy and verify
print("== proxy and verify")
px = HttpProxy()
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "http", "host": "127.0.0.1", "port": px.port, "bypass": "nothing.example"})
p, res = go(req(url=BASE + "/via"))
check("Settings > Proxy is not used: a web request goes direct, past the fake proxy", res["status"] == 200 and not px.log and hits and hits[-1]["path"] == "/via", (px.log, res["error"]))
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "http", "host": "127.0.0.1", "port": px.port, "bypass": "127.0.0.1"})
n = len(px.log); p, res = go(req(url=BASE + "/direct"))
check("an address on the bypass list goes direct", res["status"] == 200 and len(px.log) == n and hits[-1]["path"] == "/direct")
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "http", "host": "127.0.0.1", "port": 1, "bypass": ""})
p, res = go(req(url=BASE + "/x", timeout=5))
check("a proxy that is not there does not matter to a web request", res["status"] == 200 and not res["error"], res["error"])
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "none"})
p, res = go(req(url=TLS + "/tls", verify=True))
check("verify on: a self-signed certificate is refused, with the hint", res["error"].startswith("Certificate not trusted:") and "Untick Verify certificate" in res["error"], res["error"])
p, res = go(req(url=TLS + "/tls", verify=False))
check("verify off: it goes through", res["status"] == 200 and hits[-1]["path"] == "/tls", res["error"])
p, res = go(req(url=BASE + "/slow", timeout=1))
check("a timeout is explained", res["error"] == "No reply within 1 s.", res["error"])
p, res = go(req(url="http://127.0.0.1:1/", timeout=3))
check("nothing listening is explained", res["error"].startswith(("Could not connect:", "No reply within")), res["error"])
p, res = go(req(url="http://nonexistent.invalid/", timeout=3))
check("a name that does not resolve is explained", res["error"].startswith("Could not connect:"), res["error"])
cancel = threading.Event(); cancel.set()
p, res = go(req(url=BASE + "/big"))
check("a big reply is cut at 5 MB and says so", res["size"] == 6 * 1024 * 1024 and len(res["body"]) == A.MAX_BODY and res["truncated"] == 1)
p = A.build(req(url=BASE + "/big"), "", {}); res = A.send(p, cancel)
check("cancel stops reading and reports Cancelled", res["cancelled"] and res["error"] == "Cancelled." and len(res["body"]) < 6 * 1024 * 1024)

# ================================================================ showing a reply
print("== showing a reply")
p, res = go(req(url=BASE + "/j"))
text, kind = A.pretty(res["body"], res["headers"])
check("JSON is pretty-printed", kind == "json" and text.startswith("{\n  \"method\"") and json.loads(text)["path"] == "/j")
check("raw when pretty-print is off", A.pretty(res["body"], res["headers"], want=False) == (res["body"].decode(), "text"))
p, res = go(req(url=BASE + "/xml"))
text, kind = A.pretty(res["body"], res["headers"])
check("XML is indented", kind == "xml" and "\n  <a x=\"1\">\n    <b>text</b>" in text, text)
p, res = go(req(url=BASE + "/text"))
check("text in another charset is decoded by the Content-Type", A.pretty(res["body"], res["headers"]) == ("plain é", "text"))
check("JSON without a JSON content type is still pretty-printed", A.pretty(b'[1,2]', [("Content-Type", "text/plain")])[1] == "json")
check("broken JSON stays as it came", A.pretty(b'{oops', [("Content-Type", "application/json")]) == ("{oops", "text"))
check("Format JSON tidies the body and explains a bad one", A.format_json('{"a":[1,2]}') == '{\n  "a": [\n    1,\n    2\n  ]\n}' and refused(lambda: A.format_json("{x"), "not valid json"))
check("sizes read well", (A.size_text(900), A.size_text(4300), A.size_text(3 * 1024 * 1024)) == ("900 bytes", "4.2 KB", "3.0 MB"))

# ================================================================ saved requests, folders, organizations
print("== saved requests and folders")
chi = A.create_folder("Chicago"); core = A.create_folder("Core", chi)
r1 = A.save(req(name="FW status", url="https://{{host}}/api/status", folder_id=chi, auth={"type": "bearer"}), "saved-tok-1")
got = A.get(r1)
check("saved and read back with the editor state, in its folder", got["name"] == "FW status" and got["folder_id"] == chi and got["auth"]["type"] == "bearer" and got["verify"] is True and got["timeout"] == 30 and got["org"] == 0)
check("the token is in the vault under the request's name, and nowhere in the database", STORE[("netcheck", f"api-request:{r1}")] == "saved-tok-1" and A.request_secret(got) == "saved-tok-1" and b"saved-tok-1" not in db_text())
check("saving again with secret None keeps the token", (A.save({**got, "url": "https://{{host}}/api/status2"}), A.request_secret(got))[1] == "saved-tok-1")
check("the same name in the same folder is refused, naming the folder", refused(lambda: A.save(req(name="fw STATUS", url="x", folder_id=chi)), "already exists in Chicago"))
check("the same name at the top level is fine", A.save(req(name="FW status", url="x")) > 0)
check("a nameless top-level clash says so", refused(lambda: A.save(req(name="FW status", url="x")), "at the top level"))
d = A.duplicate(r1)
check("a copy gets a free name and the token comes with it", A.get(d)["name"] == "FW status (copy)" and A.request_secret(A.get(d)) == "saved-tok-1" and A.get(d)["folder_id"] == chi)
check("a second copy gets another name", A.get(A.duplicate(r1))["name"] == "FW status (copy 2)")
A.rename(d, "Renamed"); check("renamed", A.get(d)["name"] == "Renamed")
A.delete(d); check("deleting removes the row and the token", A.get(d) is None and ("netcheck", f"api-request:{d}") not in STORE)
A.save({**got, "auth": {"type": "none"}}, ""); check("saving with secret '' removes the stored token", ("netcheck", f"api-request:{r1}") not in STORE)
A.save({**A.get(r1), "auth": {"type": "bearer"}}, "saved-tok-1")
check("folders list with paths and nest", A.folder_paths()[core] == "Chicago/Core" and A.folder_descendants(chi) == {chi, core})
A.move_requests([r1], core); check("a request moves into a folder", A.get(r1)["folder_id"] == core)
A.delete_folder(core); check("deleting a folder moves its requests up a level", A.get(r1)["folder_id"] == chi)
check("the list is by name", [r["name"] for r in A.list_requests()][:3] == ["FW status", "FW status", "FW status (copy 2)"])
with db.connect() as con: con.execute("UPDATE api_requests SET params='{oops', auth='[1]', body_type='weird' WHERE id=?", (r1,))
check("damaged stored values fall back to defaults", A.get(r1)["params"] == [] and A.get(r1)["auth"]["type"] == "none" and A.get(r1)["body_type"] == "none")
A.save({**A.get(r1), "auth": {"type": "bearer"}})

print("== organizations")
acme = orgs.create("Acme Charter", "ACME"); globex = orgs.create("Globex", "GLBX")
shared = A.save(req(name="Shared ping", url="http://{{host}}/ping", shared=1, auth={"type": "bearer"}), "shared-tok")
gpid = profiles.save({"name": "shared-prof", "username": "svc", "shared": 1}, {"main": "shared-prof-secret"})
shared_prof = A.save(req(name="Shared with profile", url=BASE + "/sp", shared=1, auth={"type": "profile", "profile_id": gpid, "send_as": "bearer"}))
check("in Global the list shows Global's own requests only, Shared ones flagged", {(r["name"], r["shared"], r["org"]) for r in A.list_requests()} >= {("Shared ping", 1, 0), ("FW status", 0, 0)})
db.set_home(acme)
mine = A.save(req(name="Acme thing", url="http://{{host}}/acme", auth={"type": "bearer"}), "acme-tok")
check("an organization's request goes in its own file and vault prefix", A.get(mine)["org"] == acme and STORE[("netcheck", f"org{acme}/api-request:{mine}")] == "acme-tok")
check("an organization sees its own plus Global's Shared ones, not Global's others", {(r["name"], r["org"]) for r in A.list_requests()} == {("Acme thing", acme), ("Shared ping", 0), ("Shared with profile", 0)})
sh = next(r for r in A.list_requests() if r["name"] == "Shared ping")
check("a Shared request's token is read from Global's vault names", A.request_secret(sh) == "shared-tok")
check("an organization cannot mark its own request Shared", A.get(A.save(req(name="try", url="x", shared=1)))["shared"] == 0)
check("an organization's variables are its own", A.list_variables() == [])
A.set_variable("host", f"127.0.0.1:{PORT}")
p, res = go(sh, A.request_secret(sh), A.variable_values())
check("a Shared request is sent with the organization's own variable values", res["status"] == 200 and hits[-1]["path"] == "/ping" and hits[-1]["headers"]["authorization"] == "Bearer shared-tok")
sp = next(r for r in A.list_requests() if r["name"] == "Shared with profile")
p, res = go(sp, "", A.variable_values())
check("a Shared request with Global's profile finds that profile from an organization", res["status"] == 200 and hits[-1]["headers"]["authorization"] == "Bearer shared-prof-secret", (res["error"], hits[-1]["headers"] if hits else None))
db.set_home(globex)
check("another organization sees neither Acme's request nor its variables", {r["name"] for r in A.list_requests()} == {"Shared ping", "Shared with profile"} and A.list_variables() == [])
db.set_home(db.GLOBAL)
check("Global's own variables are separate too", [v["name"] for v in A.list_variables()] == ["host", "token"])

# ================================================================ history and the audit log
print("== history and the audit log")
A.clear_history()
r = req(url=BASE + "/h?k={{token}}", auth={"type": "apikey", "key_name": "api_key", "where": "query"}, headers=[[True, "X-Secret", "{{token}}"]])
p, res = go(r, "typed-key-1", A.variable_values())
hid = A.record(r, p, res, request_id=None)
line = audit.recent(1)[0]
check("one audit line per send, with the method, status and time", line["action"] == "api request" and line["detail"].startswith(f"GET {BASE}/h?") and "-> 200 in" in line["detail"], line["detail"])
check("the typed key and the secret variable are masked in it", "typed-key-1" not in line["detail"] and "var-secret-55" not in line["detail"] and line["detail"].count("****") == 2, line["detail"])
hrow = A.list_history()[0]
check("history keeps the editor state, status and time, never the secret", hrow["id"] == hid and hrow["url"] == BASE + "/h?k={{token}}" and hrow["auth"]["type"] == "apikey" and hrow["status"] == 200 and hrow["ms"] >= 0 and hrow["size"] > 0
      and b"typed-key-1" not in db_text() and hrow["headers"] == [[True, "X-Secret", "{{token}}"]])
p, res = go(req(url="http://nonexistent.invalid/", timeout=3))
A.record(req(url="http://nonexistent.invalid/", timeout=3), p, res)
check("a failed send is audited as failed and kept in history with its error", audit.recent(1)[0]["action"] == "api request failed" and A.list_history()[0]["error"].startswith("Could not connect") and A.list_history()[0]["status"] == 0,
      (audit.recent(1)[0], A.list_history()[0]["error"]))
db.set_setting("api_history_keep", 5)
for i in range(8):
    A.add_history(req(url=f"{BASE}/n{i}"), {"status": 200, "ms": 1, "size": 1})
check("history keeps the last N (Settings), newest first", [h["url"][-3:] for h in A.list_history()] == ["/n7", "/n6", "/n5", "/n4", "/n3"], [h["url"] for h in A.list_history()])
db.set_setting("api_history_keep", 100)
db.set_home(acme); A.add_history(req(url=BASE + "/acme-only"), {"status": 200, "ms": 1, "size": 1})
check("history is per organization", [h["url"] for h in A.list_history()] == [BASE + "/acme-only"])
db.set_home(db.GLOBAL)
check("...and Global's is its own", BASE + "/acme-only" not in [h["url"] for h in A.list_history()])
A.clear_history(); check("clear history empties it", A.list_history() == [])
def tables(org):
    with db.within(org), db.connect() as c:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
check("the migration is numbered and every organization's file has the tables", db.schema_version() >= 9 and all(
    {"api_requests", "api_folders", "api_history", "api_variables"} <= tables(o) for o in (db.GLOBAL, acme, globex)))

# ================================================================ the page
print("== the page")
from ui import apitool as U
from ui.tools import ToolsTab
tools = ToolsTab()
check("API Tester is in the Tools list under Connect", "API Tester" in [tools.tabs.tabText(i) for i in range(tools.tabs.count())] and isinstance(tools.apitest, U.ApiTesterTab))
page = tools.apitest
page.refresh()
names = lambda: [page.tree.topLevelItem(i).text(0) for i in range(page.tree.topLevelItemCount())]
check("the tree lists Global's folders and requests", "Chicago  (2)" in names() and "FW status" in names() and any(n.startswith("Shared ping") for n in names()), names())
check("the editor starts empty", page.url.text() == "" and page.method.currentText() == "GET" and page.verify.isChecked() and page.timeout.value() == 30)
item = next(it for it in page._all_items() if page.kind_of(it) == ("request", r1, 0))
page.tree.setCurrentItem(item); page._selected()
check("clicking a request loads it, with its token from the vault (masked in the box)", page.url.text() == "https://{{host}}/api/status" and page.auth_type.currentData() == "bearer" and page.token.text() == "saved-tok-1"
      and page.token.echoMode().name == "Password" and page.title.text() == "FW status", (page.url.text(), page.title.text()))
page.url.setText("https://{{host}}/api/status3")
check("an edit marks the request changed", page.title.text() == "FW status  (changed)")
state = page.state()
check("the editor state round-trips", state["url"] == "https://{{host}}/api/status3" and state["auth"]["type"] == "bearer" and state["method"] == "GET" and state["name"] == "FW status")
page.method.setCurrentText("POST"); page.body_type.setCurrentIndex(page.body_type.findData("json")); page.body.setPlainText('{"a":1}')
page.params.item(0, 1).setText("x"); page.params.item(0, 2).setText("1")
check("typing a param fills the URL's query string", page.url.text() == "https://{{host}}/api/status3?x=1", page.url.text())
page.url.setText("https://{{host}}/api/status3?y=2&x=3")
check("...and the URL fills the table", page.params.rows() == [[True, "y", "2"], [True, "x", "3"]], page.params.rows())
page.fmt_btn.click(); check("Format JSON tidies the body", page.body.toPlainText() == '{\n  "a": 1\n}')
page.save_current();
check("Save keeps the changes in place", A.get(r1)["method"] == "POST" and A.get(r1)["url"] == "https://{{host}}/api/status3?y=2&x=3" and A.get(r1)["params"] == [[True, "y", "2"], [True, "x", "3"]] and A.request_secret(A.get(r1)) == "saved-tok-1" and page.title.text() == "FW status",
      (A.get(r1)["url"], A.get(r1)["params"], page.title.text()))
page.url.setText(BASE + "/ui-send"); page.params.set_rows([]); page.auth_type.setCurrentIndex(page.auth_type.findData("none")); page.method.setCurrentText("GET"); page.body_type.setCurrentIndex(0)
def wait_sent():
    for _ in range(200):                                   # until the reply has been shown (the worker's signal is queued to the window)
        app.processEvents(); time.sleep(0.05)
        if page.status.text() not in ("Sending...", "Cancelling..."): break
hits.clear(); page.send_now(); wait_sent()
check("Send goes through the worker and shows the reply", not page.running() and hits and hits[-1]["path"] == "/ui-send" and page.status.text().startswith("200 OK") and '"path": "/ui-send"' in page.resp_body.toPlainText(), page.status.text())
check("the reply headers tab is filled", "X-Served-By: fake" in page.resp_headers.toPlainText())
check("the send is in history and the audit log", A.list_history()[0]["url"] == BASE + "/ui-send" and audit.recent(1)[0]["action"] == "api request")
page.refresh()
check("History lists it", page.history.rowCount() >= 1 and page.history.item(0, 2).text() == BASE + "/ui-send" and page.history.item(0, 3).text() == "200")
page.url.setText("http://{{nothere}}/"); page.send_now()
check("an unresolved variable is refused with the message", page.status.text() == "No value for {{nothere}}. Add it on the Variables tab." and not page.running())
page.variables.refresh()
check("the Variables tab shows the organization's variables, secret ones as dots", [page.variables.table.item(i, 0).text() for i in range(page.variables.table.rowCount())] == ["host", "token"]
      and page.variables.table.item(1, 1).text() == U.DOTS and page.variables.table.item(0, 1).text() == f"127.0.0.1:{PORT}")
page.new_request()
check("New clears the editor", page.url.text() == "" and page.title.text() == "New request" and page.current is None, (page.url.text(), page.title.text(), page.current))
page.history.selectRow(0); page._history_clicked()
check("clicking a history row loads it back", page.url.text() == BASE + "/ui-send" and page.title.text().startswith("From history"), page.title.text())
# saving a new request goes through the Save dialog
U.SaveDialog.exec = lambda self: (self.name.setText("Saved from the page"), QDialog.DialogCode.Accepted)[1]
page.new_request(); page.url.setText(BASE + "/new"); page.auth_type.setCurrentIndex(page.auth_type.findData("bearer")); page.token.setText("page-tok")
check("Save on a new request asks for a name and keeps the token in the vault", page.save_current() and page.current and page.current["name"] == "Saved from the page"
      and A.request_secret(page.current) == "page-tok" and b"page-tok" not in db_text() and page.title.text() == "Saved from the page", page.title.text())
new_id = page.current["id"]
# history from a saved request brings its secret back; from an unsaved one it does not
hits.clear(); page.url.setText(BASE + "/secure"); page.token.setText("tok-123"); page.save_current(); page.send_now(); wait_sent()
check("a saved request sends with its token", hits and hits[-1]["headers"].get("authorization") == "Bearer tok-123" and page.status.text().startswith("200"), page.status.text())
page.new_request(); page.history.selectRow(0); page._history_clicked()
check("a history row from a saved request loads its token again", page.token.text() == "tok-123" and page.url.text() == BASE + "/secure", (page.token.text(), page.status.text()))
page.token.setText("once-only"); page.url.setText(BASE + "/once"); page.send_now(); wait_sent()
page.new_request(); page.history.selectRow(0); page._history_clicked()
check("one sent from the editor without saving comes back with the token field empty and a note", page.token.text() == "" and page.status.text() == "Enter the token again: history does not keep secrets." and b"once-only" not in db_text())
check("a history row is not a saved request", page.current is None and page.title.text().startswith("From history"))
# cancel while a slow reply is in flight
page.new_request(); page.url.setText(BASE + "/slow"); page.send_now(); page.cancel_send()
check("Cancel is offered while sending", page.cancel_btn.isEnabled() and not page.send_btn.isEnabled())
wait_sent()
check("...and the result is reported as cancelled (or the slow reply arrives first)", page.status.text() == "Cancelled." or page.status.text().startswith("200 OK"), page.status.text())
# duplicate and delete from the page
page.refresh_tree(select=(0, new_id))
page.duplicate_selected()
check("Duplicate makes a copy next to it", any(r["name"] == "Saved from the page (copy)" for r in A.list_requests()))
QMessageBox.clickedButton = lambda self: next(b for b in self.buttons() if b.text() in ("Delete", "Clear"))
page.refresh_tree(select=(0, new_id)); page.delete_selected()
check("Delete removes the request and its token", A.get(new_id) is None and ("netcheck", f"api-request:{new_id}") not in STORE and page.current is None)
page.clear_history(); check("Clear history empties it", A.list_history() == [] and page.history.rowCount() == 0)
QMessageBox.clickedButton = lambda self: None
db.set_home(acme); page.refresh()
check("switching organization reloads the tree (Acme's own plus a Shared branch)", "Acme thing" in names() and any(n.startswith("Shared") for n in names()), names())
sh_item = next(it for it in page._all_items() if page.kind_of(it)[0] == "request" and page.payload[it.data(0, U.ROLE)]["name"] == "Shared with profile")
page.tree.setCurrentItem(sh_item); page._selected()
check("a Shared request opens read-only from an organization, naming Global's profile", page.title.text() == "Shared with profile  (Shared, from Global)" and page.profile.currentText().startswith("shared-prof"), (page.title.text(), page.profile.currentText()))
page.url.setText(BASE + "/copied")
U.SaveDialog.exec = lambda self: (self.name.setText("My copy"), QDialog.DialogCode.Accepted)[1]
check("Save makes the organization's own copy, pointing at Global's profile the way the organization refers to it", page.save_current() and page.current["org"] == acme and page.current["name"] == "My copy" and page.current["auth"]["profile_id"] == -gpid, page.current and page.current["auth"])
hits.clear(); page.send_now(); wait_sent()
check("...and the copy sends with that profile's secret", hits and hits[-1]["headers"].get("authorization") == "Bearer shared-prof-secret", page.status.text())
db.set_home(db.GLOBAL); page.refresh()
tools.shutdown()
check("the page shuts down cleanly", not page.running())

web.shutdown(); tls.shutdown()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
