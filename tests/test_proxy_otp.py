# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# A proxy with two-step sign-in: the one-time code goes on the end of the password. And what a proxy that answers oddly said.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\otp%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, proxy, vault
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import app as A
A.apply_look(app)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
QMessageBox.warning = staticmethod(lambda *a, **k: None)
QMessageBox.information = staticmethod(lambda *a, **k: None)


def recvn(s, n):
    out = b""
    while len(out) < n:
        c = s.recv(n - len(out))
        if not c: raise OSError("closed")
        out += c
    return out

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

class Server:
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

class Echo(Server):
    def handle(self, c):
        while True:
            d = c.recv(4096)
            if not d: return
            c.sendall(d)

class Socks5(Server):
    """A SOCKS5 proxy that asks for a user name and a password that `accept(user, password)` approves."""
    def __init__(self, accept):
        self.accept = accept; super().__init__()
    def handle(self, c):
        _, n = recvn(c, 2); recvn(c, n)
        c.sendall(b"\x05\x02"); recvn(c, 1)
        user = recvn(c, recvn(c, 1)[0]).decode(); pw = recvn(c, recvn(c, 1)[0]).decode()
        self.log.append((user, pw))
        if not self.accept(user, pw):
            c.sendall(b"\x01\x01"); return
        c.sendall(b"\x01\x00")
        _, cmd, _, atyp = recvn(c, 4)
        addr = socket.inet_ntoa(recvn(c, 4)) if atyp == 1 else recvn(c, recvn(c, 1)[0]).decode()
        port = int.from_bytes(recvn(c, 2), "big")
        up = socket.create_connection((addr, port), 5)
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); pipe(c, up)

class Says(Server):
    """A server that reads the greeting and answers with fixed bytes (and, for `then`, the login's answer)."""
    def __init__(self, first, then=None):
        self.first, self.then = first, then; super().__init__()
    def handle(self, c):
        c.recv(16); c.sendall(self.first)
        if self.then is not None:
            c.recv(300); c.sendall(self.then)
        time.sleep(0.2); c.close()

echo = Echo()
def tunnel(cfg):
    try: s = proxy.connect(cfg, "127.0.0.1", echo.port, 4); s.sendall(b"x"); r = s.recv(3); s.close(); return r == b"x", ""
    except proxy.ProxyError as e: return False, str(e)
    except Exception as e: return False, "WRONG TYPE " + type(e).__name__ + str(e)


print("== the code itself (RFC 6238 test values)")
KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                    # the RFC's "12345678901234567890"
check("the codes for the RFC's test times", proxy.totp(KEY, 59) == "287082" and proxy.totp(KEY, 1111111109) == "081804" and proxy.totp(KEY, 1234567890) == "005924" and proxy.totp(KEY, 2000000000) == "279037")
check("a key may be typed in lower case, with spaces or dashes", proxy.totp("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq", 59) == "287082")
try: proxy.totp("not a key!", 59); bad_key = ""
except proxy.ProxyError as e: bad_key = str(e)
check("a key that is not one is explained", "secret key" in bad_key, bad_key)

print("== a proxy that wants the password with a code on the end")
live = {"code": "111111"}
px = Socks5(lambda u, p: u == "joe" and p == "pw" + live["code"])
asked = []
def prompt(title, text): asked.append(text); return " " + live["code"] + " "
proxy.set_code_prompt(prompt)
cfg = proxy.Config("socks5", "127.0.0.1", px.port, "joe", "pw", otp="ask")
good, msg = tunnel(cfg)
check("asking: the code typed is added to the password", good and px.log[-1] == ("joe", "pw111111") and len(asked) == 1 and "joe" in asked[0], (good, msg, px.log))
good, msg = tunnel(cfg)
check("the same code is used again straight away, without asking again", good and len(asked) == 1 and px.log[-1] == ("joe", "pw111111"), (asked, px.log))
live["code"] = "222222"; proxy._codes.clear()
good, msg = tunnel(cfg)
check("a new code is asked for once the old one is gone", good and len(asked) == 2 and px.log[-1][1] == "pw222222")
live["code"] = "333333"
good, msg = tunnel(cfg)
check("a code the proxy refuses is not kept, and the message says it may be the code", not good and "rejected the user name or password or the one-time code" in msg and not proxy._codes, msg)
n = len(asked); live["code"] = "333333"
good, msg = tunnel(cfg)
check("so the next attempt asks again", good and len(asked) == n + 1)
only = Socks5(lambda u, p: p == "654321")
live["code"] = "654321"; proxy._codes.clear()
good, msg = tunnel(proxy.Config("socks5", "127.0.0.1", only.port, "joe", "", otp="ask"))
check("with no password, the code alone is sent", good and only.log[-1] == ("joe", "654321"), only.log)
proxy.set_code_prompt(lambda *a: ""); proxy._codes.clear()
good, msg = tunnel(cfg)
check("cancelling the question stops the connection and says why", not good and "no one-time code was entered" in msg, msg)
proxy.set_code_prompt(None)
good, msg = tunnel(cfg)
check("a run that cannot ask says so and points to the secret key", not good and "set the code to 'Make it from a secret key'" in msg, msg)

print("== a code made from a secret key")
now = time.time()
real_totp = proxy.totp
proxy.totp = lambda key, t=None, **k: real_totp(key, 59)
px2 = Socks5(lambda u, p: p == "pw287082")
good, msg = tunnel(proxy.Config("socks5", "127.0.0.1", px2.port, "joe", "pw", otp="totp", otp_key=KEY))
check("it is worked out and added without asking", good and px2.log[-1] == ("joe", "pw287082"), (good, msg, px2.log))
proxy.totp = real_totp
good, msg = tunnel(proxy.Config("socks5", "127.0.0.1", px2.port, "joe", "pw", otp="totp", otp_key=""))
check("a missing key is explained", not good and "no secret key is saved" in msg, msg)
cfgt = proxy.Config("socks5", "h", 1080, "u", "p", otp="totp", otp_key=KEY)
check("web requests get the code in the proxy address too", proxy.with_code(cfgt).password == "p" + proxy.totp(KEY) and proxy.with_code(proxy.Config("socks5", "h", 1080, "u", "p")).password == "p")
http_like = proxy.Config("http", "127.0.0.1", px2.port, "u", "p", otp="totp", otp_key=KEY)
check("an HTTP proxy gets it as well", proxy.with_code(http_like).password.startswith("p") and len(proxy.with_code(http_like).password) == 7)

print("== which proxy to use carries the one-time code setting")
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "socks5", "host": "px.corp", "port": 1080, "username": "joe", "otp": "totp"})
STORE[("netcheck", proxy.GLOBAL_SECRET)] = "pw"; STORE[("netcheck", proxy.GLOBAL_OTP)] = KEY
c = proxy.for_device({"name": "sw1", "host": "10.1.1.1"})
check("global: the setting and the key are read", c.otp == "totp" and c.otp_key == KEY and c.password == "pw")
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "socks5", "host": "px.corp", "port": 1080, "username": "joe", "otp": "ask"})
c = proxy.for_device({"name": "sw1", "host": "10.1.1.1"})
check("global: 'ask' does not read the key", c.otp == "ask" and c.otp_key == "")
own = {"name": "sw1", "host": "10.1.1.1", "proxy": json.dumps({"mode": "custom", "kind": "socks5", "host": "px2", "port": 1080, "username": "u", "otp": "totp"})}
STORE[("netcheck", "sw1:proxy-otp")] = "DEVKEY"
check("a device's own proxy has its own key", proxy.for_device(own).otp_key == "DEVKEY" and proxy.for_device({**own, "_proxy_otp_secret": "TYPED"}).otp_key == "TYPED")
check("a device without the setting has none", proxy.for_device({**own, "proxy": json.dumps({"mode": "custom", "kind": "socks5", "host": "px2", "port": 1080})}).otp == "")
check("the secret key is included in the vault's list of credentials", "service:proxy-otp" in vault.known_names() and "sw1:proxy-otp" in [db.secret_name("sw1", k) for k in db.SECRET_KINDS])

print("== what a proxy that answers oddly said")
def says(first, then=None, user="joe"):
    s = Says(first, then); return tunnel(proxy.Config("socks5", "127.0.0.1", s.port, user, "pw"))
good, msg = says(b"SSH-2.0-OpenSSH_9.6\r\n")
check("an SSH server is recognised", not good and "SSH server" in msg and "ssh -D" in msg, msg)
good, msg = says(b"HTTP/1.1 400 Bad Request\r\n\r\n")
check("an HTTP proxy is recognised", not good and "looks like an HTTP proxy" in msg, msg)
good, msg = says(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
check("a SOCKS4 answer is recognised", not good and "SOCKS4" in msg, msg)
good, msg = says(b"\x05\x03")
check("a sign-in method that is not supported is named", not good and "CHAP" in msg and "does not support" in msg, msg)
good, msg = says(b"\x05\x80")
check("a method of the proxy's own is described as such", not good and "method of its own (0x80)" in msg and "does not support" in msg, msg)
good, msg = says(b"\x05\xff")
check("'none of your methods' is explained", not good and "accepts none of the sign-in methods" in msg, msg)
good, msg = says(b"\x05\x02", b"\x05\x00")
check("an odd answer to the login is shown, and says a second step may be why", not good and "0x05 0x00" in msg and "second step" in msg, msg)
good, msg = says(b"\x05\x02", b"")
check("a proxy that hangs up after the login says so", not good and "closed the connection instead of answering the login" in msg, msg)
good, msg = says(b"")
check("a proxy that says nothing is explained", not good and "closed the connection instead of answering the greeting" in msg, msg)
good, msg = says(b"\x05\x02", b"\x01\x00" + b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
check("a refused connection names the reason", not good and "not allowed by the proxy's rules" in msg and "127.0.0.1" in msg, msg)
good, msg = tunnel(proxy.Config("socks5", "127.0.0.1", Says(b"\x05\x02").port, "", ""))
check("a proxy that wants a login when none is set up says to enter one", not good and "enter them" in msg, msg)

print("== the Settings page")
import ui.settings_pages.network as N
db.set_setting("proxy", dict(proxy.DEFAULTS)); STORE.pop(("netcheck", proxy.GLOBAL_OTP), None)
page = N.ProxyPage(); page.load()
check("the page offers the code setting, off to begin with", page.otp.count() == 3 and page.otp.currentData() == "")
page.mode.setCurrentIndex(page.mode.findData("manual")); page.kind.setCurrentIndex(page.kind.findData("socks5"))
page.host.setText("127.0.0.1"); page.port.setValue(px2.port); page.user.setText("joe"); page.password.setText("pw")
page.otp.setCurrentIndex(page.otp.findData("totp")); page.adapt()
check("choosing a secret key shows its box", page.form.isRowVisible(page.otp_key) and page.form.isRowVisible(page.otp_note))
check("saving without a key is refused", any("secret key" in m for m in page.validate()), page.validate())
page.otp_key.setText("not a key!")
check("a key that is not valid is refused", any("not valid" in m for m in page.validate()), page.validate())
page.otp_key.setText("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
check("a good one passes", page.validate() == [])
page.save()
saved = db.get_setting("proxy")
check("saved: the setting is in the database, the key only in Credential Manager", saved["otp"] == "totp" and "GEZD" not in json.dumps(saved).upper() and STORE[("netcheck", proxy.GLOBAL_OTP)] == KEY, STORE.get(("netcheck", proxy.GLOBAL_OTP)))
check("reloaded: the key box is empty and the page says one is saved", page.otp.currentData() == "totp" and page.otp_key.text() == "" and "A key is saved" in page.otp_note.text())
check("and a save with the box empty keeps it", (page.validate() == [], page.save(), STORE.get(("netcheck", proxy.GLOBAL_OTP)) == KEY)[2])
page.otp.setCurrentIndex(page.otp.findData("ask")); page.save()
check("changing to 'ask' removes the saved key", ("netcheck", proxy.GLOBAL_OTP) not in STORE and db.get_setting("proxy")["otp"] == "ask")
proxy.totp = lambda key, t=None, **k: real_totp(key, 59)
page.otp.setCurrentIndex(page.otp.findData("totp")); page.otp_key.setText(KEY); page.test_to.setText(f"127.0.0.1:{echo.port}"); page.test()
proxy.totp = real_totp
check("the Test button uses the code too", page.test_out.text().startswith("OK:") and px2.log[-1] == ("joe", "pw287082"), (page.test_out.text(), px2.log[-3:]))

print("== the question, from a worker thread")
from ui import otpprompt
from PySide6.QtWidgets import QInputDialog
shown = []
class FakeDialog:
    def __init__(self, parent=None): pass
    def setWindowTitle(self, t): shown.append(t)
    def setLabelText(self, t): shown.append(t)
    def setTextEchoMode(self, m): pass
    def setWindowFlag(self, *a): pass
    def exec(self): return 1
    def textValue(self): return "424242"
otpprompt._real_dialog = otpprompt.QInputDialog
otpprompt.QInputDialog = FakeDialog
otpprompt.install()
check("installing it hands the question to the proxy code", proxy.CODE_PROMPT is otpprompt.ask)
check("asked on the main thread, it answers directly", otpprompt.ask("Code", "for joe") == "424242" and shown[0] == "Code" and "authenticator" in shown[1])
got = {}
t = threading.Thread(target=lambda: got.update(code=otpprompt.ask("Code", "for joe")), daemon=True); t.start()
end = time.time() + 5
while t.is_alive() and time.time() < end: app.processEvents(); time.sleep(0.01)
check("asked on a worker thread, the main thread shows it and the worker gets the answer", got.get("code") == "424242", got)
otpprompt.QInputDialog = otpprompt._real_dialog

print("== the indicator along the bottom")
import types
from ui.statusstrip import StatusStrip
strip = StatusStrip(types.SimpleNamespace())
def settle(strip):
    end = time.time() + 6
    while time.time() < end:
        app.processEvents(); time.sleep(0.02)
        if not strip._probing: break
def manual(host, port, kind="socks5"):
    db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": kind, "host": host, "port": port, "username": "joe"})
    strip.probe_state = None; strip.restyle(); settle(strip)
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "none"}); strip.restyle()
check("with no proxy it says so, quietly", strip.proxy.text() == "No proxy" and "directly" in strip.proxy.toolTip())
manual("127.0.0.1", px2.port)
check("a proxy that answers is shown as connected", "Proxy connected" in strip.proxy.text() and "answers" in strip.proxy.toolTip(), strip.proxy.text())
n = len(px2.log)
strip.restyle(); settle(strip)
check("looking does not sign in, so it cannot use up a code", len(px2.log) == n, px2.log[n:])
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dport = dead.getsockname()[1]; dead.close()
manual("127.0.0.1", dport)
check("one that does not answer is shown as disconnected, with why", "Proxy disconnected" in strip.proxy.text() and "did not answer" in strip.proxy.toolTip(), (strip.proxy.text(), strip.proxy.toolTip()))
manual("127.0.0.1", Says(b"SSH-2.0-OpenSSH_9.6\r\n").port)
check("one that is really an SSH server says that", "Proxy disconnected" in strip.proxy.text() and "SSH server" in strip.proxy.toolTip(), strip.proxy.toolTip())
manual("127.0.0.1", px2.port)
proxy.LAST[f"127.0.0.1:{px2.port}"] = (False, time.time() + 5, "rejected the user name or password")
strip.refresh()
check("a proxy that answers but refused the last real connection is flagged", "refused the last connection" in strip.proxy.text() and "rejected the user name" in strip.proxy.toolTip(), strip.proxy.text())
proxy.LAST[f"127.0.0.1:{px2.port}"] = (True, time.time(), "")
strip.refresh()
check("and a later good one clears it", "Proxy connected" in strip.proxy.text() and "worked" in strip.proxy.toolTip() and "refused" not in strip.proxy.text())
proxy.LAST.clear()
bad_cfg = proxy.Config("socks5", "127.0.0.1", px2.port, "joe", "bad")
tunnel(bad_cfg)
check("a real connection that is refused is recorded", proxy.last_result(bad_cfg)[0] is False and "rejected" in proxy.last_result(bad_cfg)[2], proxy.LAST)
down = Says(b"\x05\x00", b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); proxy.LAST.clear()
cfg_down = proxy.Config("socks5", "127.0.0.1", down.port)
good, msg = tunnel(cfg_down)
check("a target that was down is not blamed on the proxy", not good and "refused by the target" in msg and proxy.last_result(cfg_down)[0] is True, (msg, proxy.LAST))
live["code"] = "777777"; proxy._codes.clear(); proxy.set_code_prompt(lambda *a: "777777")
good, msg = tunnel(cfg)
check("a good connection is recorded as such", good and proxy.last_result(cfg)[0] is True, msg)
seen = []
strip.navigate.connect(lambda a, b: seen.append((a, b))); strip.proxy.clicked.emit()
check("clicking it opens Settings > Proxy", seen == [("Settings", "Proxy")])
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "system"})

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
