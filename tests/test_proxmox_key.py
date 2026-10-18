# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Proxmox VE: making an API token with an administrator's sign-in, against a simulated Proxmox over real HTTPS. And HTTP errors in a run.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\pvekey%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingpv%d" % int(time.time()))
from core import agents, db, pvekey
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import http.server, ssl, threading, urllib.parse
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

# ---- a Proxmox that behaves like the real one where it matters
STATE = {"tfa": False, "existing": set(), "acl_ok": True, "log": []}
class PVE(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def _form(self):
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()).items()}
    def _authed(self):
        return "PVEAuthCookie=TICKET-1" in (self.headers.get("Cookie") or "") and self.headers.get("CSRFPreventionToken") == "CSRF-1"
    def do_POST(self):
        form = self._form(); path = urllib.parse.unquote(self.path); STATE["log"].append(("POST", path, form, self.headers.get("Cookie"), self.headers.get("CSRFPreventionToken")))
        if path == "/api2/json/access/ticket":
            if form.get("password") != "right-pw": return self._send(401, {"data": None})
            if STATE["tfa"]: return self._send(200, {"data": {"NeedTFA": 1, "ticket": "PVE:tfa", "CSRFPreventionToken": "x"}})
            return self._send(200, {"data": {"ticket": "TICKET-1", "CSRFPreventionToken": "CSRF-1", "username": form["username"]}})
        if path.startswith("/api2/json/access/users/") and "/token/" in path:
            if not self._authed(): return self._send(401, {"data": None})
            user, name = path[len("/api2/json/access/users/"):].split("/token/")
            if (user, name) in STATE["existing"]: return self._send(500, {"data": None, "message": "create token failed: Token already exists.\n"})
            return self._send(200, {"data": {"full-tokenid": f"{user}!{name}", "info": {"privsep": "1"}, "value": "11111111-2222-3333-4444-555555555555"}})
        self._send(404, {})
    def do_PUT(self):
        form = self._form(); STATE["log"].append(("PUT", self.path, form, self.headers.get("Cookie"), self.headers.get("CSRFPreventionToken")))
        if self.path == "/api2/json/access/acl" and self._authed() and STATE["acl_ok"]: return self._send(200, {"data": None})
        self._send(403, {"data": None, "message": "Permission check failed"})
cert, keyf = agents.ensure_cert()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, keyf)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PVE); srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
DEV = {"name": "pve-1", "host": "127.0.0.1", "port": srv.server_address[1], "verify_ssl": 0}

print("== making the token")
token, note = pvekey.create_token(DEV, "root@pam", "right-pw")
check("a good sign-in returns the token in the form Proxmox expects, as user@realm!name=secret", token == "root@pam!toner=11111111-2222-3333-4444-555555555555" and note == "", (token, note))
log = STATE["log"]
check("it signs in with the user (realm included) and the password in the body of a POST", log[0][:3] == ("POST", "/api2/json/access/ticket", {"username": "root@pam", "password": "right-pw"}))
check("then makes the token with the ticket and CSRF token, with privilege separation on", log[1][1] == "/api2/json/access/users/root@pam/token/toner" and log[1][3] == "PVEAuthCookie=TICKET-1" and log[1][4] == "CSRF-1" and log[1][2]["privsep"] == "1")
check("and gives that token the read-only role on / (so it can read, and change nothing)", log[2][0] == "PUT" and log[2][2] == {"path": "/", "roles": "PVEAuditor", "tokens": "root@pam!toner", "propagate": "1"} and log[2][4] == "CSRF-1", log[2])
check("the account's password is never in the token or the note", "right-pw" not in token + note)
STATE["existing"].add(("root@pam", "toner"))
token, note = pvekey.create_token(DEV, "root@pam", "right-pw")
check("when 'toner' exists already, another name is used, not an error", token.startswith("root@pam!toner-") and token.endswith("=11111111-2222-3333-4444-555555555555"), token)
STATE["existing"].add(("root@pam", "toner")); STATE["acl_ok"] = False
token, note = pvekey.create_token(DEV, "root@pam", "right-pw")
check("if the read-only role cannot be given, the token is still returned, with what to do by hand", token and "PVEAuditor" in note and "Datacenter > Permissions" in note and token.split("=")[0] in note, note)
STATE["acl_ok"] = True

print("== when it does not work")
def fails(user="root@pam", pw="right-pw", dev=DEV):
    try:
        pvekey.create_token(dev, user, pw)
        return ""
    except ValueError as e:
        return str(e)
m = fails(pw="wrong")
check("a wrong password is said so, with the realm hint", "refused that user name or password" in m and "root@pam" in m and "wrong" not in m, m)
n = len(STATE["log"]); m = fails(user="root")
check("a user without a realm is caught before anything is sent", "with its realm" in m and len(STATE["log"]) == n, m)
m = fails(user="", pw="")
check("nothing entered is caught too", "Enter the administrator" in m and len(STATE["log"]) == n)
STATE["tfa"] = True; m = fails(); STATE["tfa"] = False
check("an account with two-factor sign-in is explained, and what to do instead", "two-factor" in m and "API Tokens" in m, m)
m = fails(dev={**DEV, "verify_ssl": 1})
check("with certificate checking on, an untrusted certificate is explained", "certificate is not trusted" in m, m)
srv.shutdown(); srv.server_close()
m = fails()
check("a closed port is explained, with the usual port", "Could not reach Proxmox" in m and "8006" in m, m)

print("== the device dialog")
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
from ui import keydialog
infos, warned = [], []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.information = staticmethod(lambda *a, **k: infos.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
d = I.DeviceDialog(); d.show(); app.processEvents()
d.vendor.setCurrentIndex(d.vendor.findData("proxmox")); app.processEvents(); d.tabs.setCurrentWidget(d.page_access)
check("a Proxmox device has its own button, worded for Proxmox", d.get_key.isVisibleTo(d.page_access) and d.get_key.text() == "Get API token from Proxmox...", d.get_key.text())
d.vendor.setCurrentIndex(d.vendor.findData("paloalto")); app.processEvents()
check("Palo Alto keeps its own wording", d.get_key.text() == "Get API key from the firewall...")
d.vendor.setCurrentIndex(d.vendor.findData("opnsense")); app.processEvents()
check("and the others have none", not d.get_key.isVisibleTo(d.page_access))
d.vendor.setCurrentIndex(d.vendor.findData("proxmox")); app.processEvents()
d.name.setText("pve-1"); d.host.setText("10.0.0.40")
seen = []
real_exec = keydialog.KeyDialog.exec
def fake_exec(self):
    seen.append((self.spec["title"], dict(self.dev))); self.key, self.note = "root@pam!toner=abc", "The token was made, but not given the role."; return 1
keydialog.KeyDialog.exec = fake_exec
d.get_key.click()
check("the Proxmox dialog is given this device, and the token lands in the box", seen and seen[0][0] == "Get an API token from Proxmox" and seen[0][1]["host"] == "10.0.0.40" and seen[0][1]["vendor"] == "proxmox" and d.secret.text() == "root@pam!toner=abc", (seen, d.secret.text()))
check("a note about the role is shown to the person", infos and "not given the role" in infos[-1], infos)
keydialog.KeyDialog.exec = real_exec
dlg = keydialog.KeyDialog({"host": "x"}, "proxmox")
check("the window explains the read-only role and asks for the realm", "PVEAuditor" in dlg.findChildren(__import__("PySide6.QtWidgets", fromlist=["x"]).QLabel)[0].text() and dlg.user.placeholderText() == "root@pam")
d.reject()

print("== an HTTP error in a run says the code, not the address")
from core.runner import run_one
import drivers.meraki as ME, drivers.unifi as UN
class R:
    def __init__(self, status): self.status_code, self.headers, self.links = status, {}, {}
    def raise_for_status(self):
        import requests; e = requests.HTTPError(f"{self.status_code} Client Error: Unauthorized for url: https://api.meraki.com/api/v1/organizations"); e.response = self; raise e
    def json(self): return []
ME.requests.get = lambda *a, **k: R(401)
th = db.get_thresholds()
rows = run_one({"name": "mer", "vendor": "meraki", "host": "127.0.0.1", "password": "k", "checkopts": "", "location": ""}, th, {**db.runtime_options(), "retries": 2, "retry_delay": 0})
check("Meraki with a bad key: one 'connection' row that says what happened", len(rows) == 1 and rows[0].message == "the device's API answered HTTP 401: the login or key was not accepted", rows)
check("... and no address in it", "api.meraki.com" not in rows[0].message and "http" not in rows[0].message.lower().replace("api answered http", ""))
UN.requests.Session = lambda: type("S", (), {"verify": True, "proxies": {}, "headers": {}, "post": lambda self, *a, **k: R(401)})()
rows = run_one({"name": "uni", "vendor": "unifi", "host": "127.0.0.1", "username": "u", "password": "k", "checkopts": "", "location": ""}, th, {**db.runtime_options(), "retries": 0})
check("the older UniFi login with a bad password says the same", rows[0].message.startswith("the device's API answered HTTP 401"), rows)
class Weird(Exception): pass
check("other errors read as they did", __import__("drivers.base", fromlist=["x"]).Driver.explain(Weird("boom")) == "Weird: boom")

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
