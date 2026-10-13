# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Palo Alto: getting an API key from the firewall with an administrator's sign-in.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\panoskey%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingpk%d" % int(time.time()))
from core import db, panos
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import requests
REAL_POST = requests.post                      # the fakes below replace it on the requests module itself
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

class Resp:
    def __init__(self, body=b"", status=200): self.content, self.status_code = body, status
GOOD = b'<response status="success"><result><key>LUFRPT1abcDEF==</key></result></response>'
DENIED = b'<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>'
sent = []
def post(answer):
    def fn(url, data=None, **kw):
        sent.append({"url": url, "data": dict(data or {}), **kw})
        if isinstance(answer, Exception): raise answer
        return answer
    return fn
DEV = {"name": "PaloVM", "host": "10.0.0.25", "port": 0, "verify_ssl": 0}

def keygen(answer, user="admin", pw="s3cret!", dev=DEV):
    panos.requests.post = post(answer)
    try:
        return panos.keygen(dev, user, pw), ""
    except ValueError as e:
        return None, str(e)

print("== asking the firewall")
key, err = keygen(Resp(GOOD))
check("a good sign-in returns the key", key == "LUFRPT1abcDEF==" and err == "", (key, err))
call = sent[-1]
check("the request goes to the firewall's API over HTTPS", call["url"] == "https://10.0.0.25:443/api/" and call["verify"] is False, call["url"])
check("the password is in the body of the request, never in the address", call["data"] == {"type": "keygen", "user": "admin", "password": "s3cret!"} and "s3cret" not in call["url"] and "params" not in call)
key, err = keygen(Resp(GOOD), dev={**DEV, "port": 4443, "verify_ssl": 1})
check("the device's port and 'verify certificate' are used", sent[-1]["url"] == "https://10.0.0.25:4443/api/" and sent[-1]["verify"] is True)
key, err = keygen(Resp(DENIED, 403))
check("a wrong password is said so, with what the firewall said", key is None and "refused that user name or password (Invalid Credential)" in err and "s3cret" not in err, err)
key, err = keygen(Resp(b"", 403))
check("with no message the code is named", "(HTTP 403)" in err, err)
key, err = keygen(Resp(b'<response status="error"><msg>Something odd happened</msg></response>'))
check("another answer from the firewall is shown as it is", err == "The firewall answered: Something odd happened", err)
key, err = keygen(Resp(b"<html>login</html>", 200))
check("a web page instead of an API (wrong address) is explained", "did not give a key" in err and "management address" in err, err)
key, err = keygen(Resp(b'<response status="success"><result></result></response>'))
check("a success with no key in it is not accepted", key is None and "did not give a key" in err)
key, err = keygen(Resp(GOOD), user="", pw="x")
n = len(sent); key, err = keygen(Resp(GOOD), user="", pw="x")
check("nothing is sent without a user name and a password", key is None and "Enter the administrator" in err and len(sent) == n)
key, err = keygen(Resp(GOOD), user="  ", pw="")
check("... and nothing went over the wire", "Enter the administrator" in err and len(sent) == n)
for exc, word in ((requests.exceptions.ConnectTimeout("t"), "did not answer"), (requests.exceptions.ConnectionError("refused"), "Could not reach"),
                  (requests.exceptions.SSLError("bad cert"), "certificate is not trusted")):
    key, err = keygen(exc)
    check(f"{type(exc).__name__} is explained in words", word in err and "refused" not in err.replace("Could not reach", ""), err)

print("== over a real HTTPS connection")
import http.server, ssl, threading, urllib.parse
from core import agents
got = {}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        got.update(path=self.path, form=urllib.parse.parse_qs(body), ctype=self.headers.get("Content-Type"))
        ok_login = got["form"].get("password") == ["right-pw"]
        out = GOOD if ok_login else DENIED
        self.send_response(200 if ok_login else 403); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
cert, keyf = agents.ensure_cert()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, keyf)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
requests.post = REAL_POST
real_dev = {"name": "PaloVM", "host": "127.0.0.1", "port": srv.server_address[1], "verify_ssl": 0}
check("a real firewall-like server gives the key", panos.keygen(real_dev, "admin", "right-pw") == "LUFRPT1abcDEF==")
check("it was a form POST to /api/ with no password in the path", got["path"] == "/api/" and got["ctype"] == "application/x-www-form-urlencoded" and got["form"] == {"type": ["keygen"], "user": ["admin"], "password": ["right-pw"]}, got)
try: panos.keygen(real_dev, "admin", "wrong"); check("the wrong password is refused", False)
except ValueError as e: check("the wrong password is refused", "refused that user name or password (Invalid Credential)" in str(e), e)
try: panos.keygen({**real_dev, "verify_ssl": 1}, "admin", "right-pw"); check("with certificate checking on, an untrusted certificate is explained", False)
except ValueError as e: check("with certificate checking on, an untrusted certificate is explained", "certificate is not trusted" in str(e), e)
srv.shutdown(); srv.server_close()
try: panos.keygen(real_dev, "admin", "right-pw", timeout=3); check("a closed port is explained", False)
except ValueError as e: check("a closed port is explained", "Could not reach the firewall" in str(e), e)

requests.post = post(Resp(GOOD))
print("== the dialog")
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
import ui.inventory as I
from ui.keydialog import KeyDialog
dlg = KeyDialog(DEV, "paloalto")
dlg.user.setText("admin"); dlg.password.setText("bad")
panos.requests.post = post(Resp(DENIED, 403))
dlg.accept()
check("a refusal is shown in the window, which stays open for another try", "refused that user name" in dlg.status.text() and dlg.result() == 0 and dlg.key == "" and dlg.password.text() == "bad")
panos.requests.post = post(Resp(GOOD))
dlg.password.setText("right"); dlg.accept()
check("a good sign-in gives the key, and the password is cleared", dlg.key == "LUFRPT1abcDEF==" and dlg.result() == 1 and dlg.password.text() == "")
check("the password is not kept anywhere on the dialog's device", "right" not in str(DEV))

print("== the device dialog")
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
d = I.DeviceDialog()
d.show(); app.processEvents()
d.vendor.setCurrentIndex(d.vendor.findData("paloalto")); app.processEvents()
d.tabs.setCurrentWidget(d.page_access)
check("a Palo Alto device has the button on its Access tab", d.get_key.isVisibleTo(d.page_access) and "firewall" in d.get_key.text())
d.vendor.setCurrentIndex(d.vendor.findData("fortinet")); app.processEvents()
check("other kinds of device do not", not d.get_key.isVisibleTo(d.page_access))
d.vendor.setCurrentIndex(d.vendor.findData("paloalto")); app.processEvents()
d.host.setText(""); d.get_key.click()
check("with no address it says to enter one first", warned and "address" in warned[-1], warned)
warned.clear(); d.host.setText("10.0.025"); d.get_key.click()
check("a mistyped address is stopped before anything is sent", warned and "not a valid IP address" in warned[-1], warned)
d.host.setText("10.0.0.25"); d.name.setText("PaloVM")
seen = []
real_exec = KeyDialog.exec
def fake_exec(self):
    seen.append(dict(self.dev))
    self.key = "LUFRPT-new-key"; return 1
KeyDialog.exec = fake_exec
d.get_key.click()
check("the dialog is given this device's address, and the key lands in the Password box", seen and seen[0]["host"] == "10.0.0.25" and seen[0]["vendor"] == "paloalto" and d.secret.text() == "LUFRPT-new-key", (seen, d.secret.text()))
check("it is saved with the device like a typed one", d.values()["name"] == "PaloVM" and d._snapshot() != d._start)
KeyDialog.exec = lambda self: 0
d.secret.setText("typed"); d.get_key.click()
check("cancelling leaves what was typed alone", d.secret.text() == "typed")
KeyDialog.exec = real_exec
d.reject()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
