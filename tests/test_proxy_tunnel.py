# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Proxy > SSH tunnel: sign in to an SSH server that asks for a one-time code (or a YubiKey touch) and send connections through it.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import http.server, json, logging, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\tun%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, proxy, tunnel
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import paramiko, requests
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
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

KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
HOSTKEY = paramiko.ECDSAKey.generate()


def pipe(a, b):
    def one(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d: break
                dst.sendall(d)
        except (OSError, EOFError): pass
        finally:
            for s in (src, dst):
                try: s.shutdown(socket.SHUT_RDWR)
                except Exception: pass
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
        except Exception: pass

class Echo(Server):
    def handle(self, c):
        while True:
            d = c.recv(4096)
            if not d: return
            c.sendall(d)

class Auth(paramiko.ServerInterface):
    def __init__(self, box):
        self.box, self.pending, self.now = box, [], box.first
    def get_allowed_auths(self, u): return self.now
    def check_auth_password(self, u, p):
        self.box.log.append(("password", u, p))
        if self.box.pw is not None and p == self.box.pw:
            if self.box.code is None: return paramiko.AUTH_SUCCESSFUL
            self.now = "keyboard-interactive"; return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_auth_interactive(self, u, sub):
        if "keyboard-interactive" not in self.now: return paramiko.AUTH_FAILED          # what a real server does
        return paramiko.server.InteractiveQuery("", "", (self.box.prompt, False))
    def check_auth_interactive_response(self, responses):
        want = self.box.code() if callable(self.box.code) else self.box.code
        self.box.log.append(("answer", list(responses)))
        return paramiko.AUTH_SUCCESSFUL if list(responses) == [want] else paramiko.AUTH_FAILED
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED
    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if destination[1] in self.box.refuse: return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.pending.append(destination); return paramiko.OPEN_SUCCEEDED

class SshBox(Server):
    """An SSH server: `first` says what it takes first, `pw` a password (then the code), `code` the one-time code."""
    def __init__(self, code="482913", pw=None, first="keyboard-interactive", prompt="Verification code: ", refuse=()):
        self.code, self.pw, self.first, self.prompt, self.refuse = code, pw, first, prompt, set(refuse); super().__init__()
    def handle(self, c):
        t = paramiko.Transport(c); t.add_server_key(HOSTKEY); srv = Auth(self); t.start_server(server=srv)
        while t.is_active():
            chan = t.accept(1)
            if chan is None: continue
            host, port = srv.pending.pop(0); self.log.append(("channel", host, port))
            def go(chan=chan, host=host, port=port):
                try: up = socket.create_connection((host, port), 5)
                except OSError: chan.close(); return
                pipe(chan, up)
            threading.Thread(target=go, daemon=True).start()

hits = []
class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.path); self.send_response(200); self.send_header("Content-Length", "7"); self.end_headers(); self.wfile.write(b"via-ssh")
    def log_message(self, *a): pass
web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target); threading.Thread(target=web.serve_forever, daemon=True).start()

echo = Echo()
asked = []
def hook(title, text, secret=False):
    asked.append((title, text, secret)); return answers.pop(0) if answers else ""
answers = []
proxy.set_code_prompt(hook)
def reach(cfg, port=None):
    try: s = proxy.connect(cfg, "127.0.0.1", port or echo.port, 6); s.sendall(b"hi"); r = s.recv(4); s.close(); return r == b"hi", ""
    except OSError as e: return False, str(e)
def cfg_for(box, **kw): return proxy.Config("tunnel", "127.0.0.1", box.port, "joe", **kw)


print("== a server that asks for a code")
box = SshBox(); c1 = cfg_for(box, otp="ask")
answers[:] = ["482913"]
good, msg = reach(c1)
check("the question is asked, answered and the connection goes through", good and len(asked) == 1 and tunnel.is_open(c1), (msg, asked))
check("the box says what the server said and mentions the YubiKey", "Verification code" in asked[0][1] and "YubiKey" in asked[0][1] and asked[0][0] == "One-time code" and not asked[0][2], asked)
check("the answer reached the server, and the channel was opened to the target", ("answer", ["482913"]) in box.log and ("channel", "127.0.0.1", echo.port) in box.log, box.log)
good, msg = reach(c1)
check("the next connection uses the open tunnel without asking again", good and len(asked) == 1 and len([l for l in box.log if l[0] == "answer"]) == 1)
check("the probe says it is open", proxy.probe(c1) == (True, "SSH tunnel 127.0.0.1:%d is open" % box.port), proxy.probe(c1))
t = tunnel.get(c1, connect=False)
s = socket.create_connection(("127.0.0.1", t.port), 3); s.sendall(b"\x05\x01\x00"); got = s.recv(2); s.close()
check("its local end refuses anyone who has no password", got == b"\x05\xff", got)
s = socket.create_connection(("127.0.0.1", t.port), 3); s.sendall(b"\x05\x01\x02"); s.recv(2); s.sendall(b"\x01\x05toner\x05wrong"); got = s.recv(2); s.close()
check("and a wrong one", got == b"\x01\x01", got)
tunnel.close(c1)
check("closing it closes it", not tunnel.is_open(c1) and proxy.probe(c1)[0] is False)

print("== a wrong code")
box2 = SshBox(); c2 = cfg_for(box2, otp="ask")
answers[:] = ["000000", "482913"]; asked.clear()
good, msg = reach(c2)
check("is refused with a message that names the code", not good and "rejected the sign-in" in msg and "one-time code" in msg and not tunnel.is_open(c2), msg)
good, msg = reach(c2)
check("and the next try asks again, and works", good and len(asked) == 2 and tunnel.is_open(c2), (msg, asked))
tunnel.close(c2)
answers[:] = [""]; asked.clear()
good, msg = reach(c2)
check("cancelling the box stops it and says why", not good and "no one-time code was entered" in msg, msg)

print("== a password first, then the code")
box3 = SshBox(pw="s3cret", first="password"); c3 = cfg_for(box3, password="s3cret", otp="ask")
answers[:] = ["482913"]; asked.clear()
good, msg = reach(c3)
check("the saved password is sent, only the code is asked for", good and ("password", "joe", "s3cret") in box3.log and len(asked) == 1 and "code" in asked[0][1].lower(), (msg, box3.log, asked))
tunnel.close(c3)
box3b = SshBox(pw="s3cret", first="password"); c3b = cfg_for(box3b, password="nope", otp="ask")
good, msg = reach(c3b)
check("a wrong password is refused", not good and "rejected the sign-in" in msg, msg)
box3c = SshBox(pw="s3cret", first="password"); c3c = cfg_for(box3c, otp="ask")
answers[:] = ["s3cret", "482913"]; asked.clear()
good, msg = reach(c3c)
check("with no saved password it asks for it, hidden, and then for the code", good and asked[0][2] is True and asked[0][0] == "Password" and asked[1][0] == "One-time code", (msg, asked))
tunnel.close(c3c)

print("== a server that only asks questions, with the password saved")
box4 = SshBox(); c4 = cfg_for(box4, password="unused", otp="ask")
answers[:] = ["482913"]
good, msg = reach(c4)
check("a password the server does not take is skipped", good, msg)
tunnel.close(c4)

print("== a code made from a secret key")
box5 = SshBox(code=lambda: proxy.totp(KEY)); c5 = cfg_for(box5, otp="totp", otp_key=KEY)
answers[:] = []; asked.clear()
good, msg = reach(c5)
check("it is worked out and answered without asking", good and not asked, (msg, asked))
tunnel.close(c5)

print("== the server will not carry a connection")
box6 = SshBox(refuse=[echo.port]); c6 = cfg_for(box6, otp="ask")
answers[:] = ["482913"]
good, msg = reach(c6)
check("the refusal is described and does not count against the tunnel", not good and "not allowed by the proxy's rules" in msg and proxy.last_result(c6)[0] is True, (msg, proxy.LAST))
check("and the tunnel stays open", tunnel.is_open(c6))

print("== web requests go through it too")
kw = proxy.requests_kwargs(None) if False else {"proxies": {"http": proxy.effective(c6).url(), "https": proxy.effective(c6).url()}}
r = requests.get(f"http://127.0.0.1:{web.server_address[1]}/x", timeout=8, **kw)
check("an address for web requests is the tunnel's local end, with its password", kw["proxies"]["http"].startswith("socks5h://toner:") and "@127.0.0.1:" in kw["proxies"]["http"])
check("and a request through it arrives", r.text == "via-ssh" and hits == ["/x"] and ("channel", "127.0.0.1", web.server_address[1]) in box6.log, (r.text, hits))
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "tunnel", "host": "127.0.0.1", "port": box6.port, "username": "joe", "otp": "ask"})
global_kw = proxy.requests_kwargs({"name": "x", "host": "10.9.9.9"})
check("the global setting produces the same through requests_kwargs", global_kw["proxies"]["https"].startswith("socks5h://toner:"), global_kw)
tunnel.close(c6)

print("== a server that is not there")
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dport = dead.getsockname()[1]; dead.close()
good, msg = reach(proxy.Config("tunnel", "127.0.0.1", dport, "joe", otp="ask"))
check("is explained", not good and "could not reach the proxy" in msg, msg)
class NotSsh(Server):
    def handle(self, c): c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); time.sleep(0.3); c.close()
good, msg = reach(proxy.Config("tunnel", "127.0.0.1", NotSsh().port, "joe", otp="ask"))
check("something that is not SSH is explained", not good and "SSH tunnel" in msg and "WRONG" not in msg, msg)
proxy.set_code_prompt(None)
box7 = SshBox(); good, msg = reach(cfg_for(box7, otp="ask"))
check("a run with no one to ask says so", not good and "can only ask for it while you are at the window" in msg, msg)
proxy.set_code_prompt(hook)

print("== the Settings page")
import ui.settings_pages.network as N
box8 = SshBox()
db.set_setting("proxy", dict(proxy.DEFAULTS))
page = N.ProxyPage(); page.load()
page.mode.setCurrentIndex(page.mode.findData("manual")); page.adapt()
check("the type list has the tunnel", page.kind.findData("tunnel") >= 0 and "SSH tunnel" in page.kind.itemText(page.kind.findData("tunnel")))
check("by default the port is the HTTP one", page.port.value() == 8080)
page.kind.setCurrentIndex(page.kind.findData("tunnel"))
check("choosing the tunnel brings port 22 and an explanation", page.port.value() == 22 and page.form.isRowVisible(page.tunnel_note) and page.form.isRowVisible(page.tunnel_close_row))
page.kind.setCurrentIndex(page.kind.findData("socks5"))
check("choosing SOCKS5 brings 1080 and hides it", page.port.value() == 1080 and not page.form.isRowVisible(page.tunnel_note))
page.kind.setCurrentIndex(page.kind.findData("tunnel")); page.port.setValue(2222); page.kind.setCurrentIndex(page.kind.findData("socks4"))
check("a port set by hand is left alone", page.port.value() == 2222)
page.kind.setCurrentIndex(page.kind.findData("tunnel")); page.port.setValue(box8.port); page.host.setText("127.0.0.1"); page.user.setText("joe")
page.otp.setCurrentIndex(page.otp.findData("ask")); page.adapt()
check("the one-time code note speaks of the server's question", "server's question" in page.otp_note.text(), page.otp_note.text())
page.save()
answers[:] = ["482913"]; asked.clear()
page.test_to.setText(f"127.0.0.1:{echo.port}"); page.test()
check("the Test button signs in and tries a connection", page.test_out.text().startswith("OK:") and len(asked) == 1, (page.test_out.text(), asked))
cfg_page = proxy.global_config()
check("the tunnel stays open afterwards", tunnel.is_open(cfg_page))
page.save()
check("saving with nothing changed keeps it open", tunnel.is_open(cfg_page))
page.host.setText("localhost"); page.save()
check("saving a different server closes it", not tunnel.is_open(cfg_page))
page.host.setText("127.0.0.1"); page.save()
page._close_tunnel()
check("the button closes the tunnel and says so", "tunnel is closed" in page.test_out.text())

print("== the indicator along the bottom")
import types
from ui.statusstrip import StatusStrip
strip = StatusStrip(types.SimpleNamespace())
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "tunnel", "host": "127.0.0.1", "port": box8.port, "username": "joe", "otp": "ask"})
tunnel.close_all(); strip.restyle()
check("a tunnel that is not open is disconnected, and says to click", "Proxy disconnected" in strip.proxy.text() and "Click to sign in" in strip.proxy.toolTip(), (strip.proxy.text(), strip.proxy.toolTip()))
answers[:] = ["482913"]; asked.clear()
strip._proxy_clicked()
check("clicking shows that it is signing in", "signing in" in strip.proxy.text())
end = time.time() + 15
while strip.opening and time.time() < end: app.processEvents(); time.sleep(0.02)
app.processEvents()
check("then it is connected", "Proxy connected" in strip.proxy.text() and "is open" in strip.proxy.toolTip() and len(asked) == 1, (strip.proxy.text(), strip.proxy.toolTip(), asked))
seen = []; strip.navigate.connect(lambda a, b: seen.append((a, b))); strip._proxy_clicked()
check("clicking it when it is open opens Settings > Proxy", seen == [("Settings", "Proxy")])
tunnel.close_all(); proxy.set_code_prompt(lambda *a, **k: "000000")
strip._proxy_clicked()
end = time.time() + 15
while strip.opening and time.time() < end: app.processEvents(); time.sleep(0.02)
app.processEvents()
check("a sign-in that fails says why in the tooltip", "Proxy disconnected" in strip.proxy.text() and "rejected the sign-in" in strip.proxy.toolTip(), strip.proxy.toolTip())
tunnel.close_all()

print("== the device's own proxy")
from ui.inventory import DeviceDialog
dd = DeviceDialog()
dd.proxy_mode.setCurrentIndex(dd.proxy_mode.findData("custom"))
check("a device can use a tunnel too, with 22 as its port", dd.proxy_kind.findData("tunnel") >= 0 and (dd.proxy_kind.setCurrentIndex(dd.proxy_kind.findData("tunnel")), dd.proxy_port.value())[1] == 22)
dd.name.setText("branch"); dd.host.setText("10.2.2.2"); dd.proxy_host.setText("127.0.0.1"); dd.proxy_user.setText("joe")
dd.proxy_otp.setCurrentIndex(dd.proxy_otp.findData("totp")); dd.proxy_otp_key.setText("gezd gnbv")
v = dd.values()
check("it is saved as a tunnel, with the key kept apart", v["proxy"]["kind"] == "tunnel" and v["proxy"]["port"] == 22 and v["proxy"]["otp"] == "totp" and dd.proxy_secrets() == {"proxy_otp": "GEZDGNBV"}, (v["proxy"], dd.proxy_secrets()))
imp = __import__("core.importer", fromlist=["x"])
check("the import file may say tunnel", "tunnel" in dict(proxy.KINDS))

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
