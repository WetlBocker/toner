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
DUO_MENU = ("Duo two-factor login for joe\n\nEnter a passcode or select one of the following options:\n\n"
            " 1. Duo Push to XXX-XXX-1234\n 2. Phone call to XXX-XXX-1234\n 3. SMS passcodes to XXX-XXX-1234\n\nPasscode or option (1-3): ")


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
        if "password" not in self.now: return paramiko.AUTH_FAILED                   # what a real server does
        if self.box.duo: time.sleep(0.3); return paramiko.AUTH_FAILED                 # PAM with Duo cannot ask its question here
        if self.box.pw is not None and p == self.box.pw:
            if self.box.code is None: return paramiko.AUTH_SUCCESSFUL
            self.now = "keyboard-interactive"; return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_auth_publickey(self, u, key):
        self.box.log.append(("publickey", u, key.get_base64()))
        if "publickey" in self.now and key.get_base64() in self.box.keys:
            if self.box.code is None: return paramiko.AUTH_SUCCESSFUL
            self.now = "keyboard-interactive"; return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_auth_interactive(self, u, sub):
        if "keyboard-interactive" not in self.now: return paramiko.AUTH_FAILED          # what a real server does
        if self.box.duo:                                                                # PAM: the password, then Duo
            self.stage = 0
            return paramiko.server.InteractiveQuery("", "", ("Password: ", False))
        return paramiko.server.InteractiveQuery("", "", (self.box.prompt, False))
    def check_auth_none(self, u):
        self.box.log.append(("none", u))
        if self.box.hangup: threading.Timer(0, self.t.close).start(); time.sleep(0.5)     # gone before it answers
        return paramiko.AUTH_FAILED
    def check_auth_interactive_response(self, responses):
        want = self.box.code() if callable(self.box.code) else self.box.code
        self.box.log.append(("answer", list(responses)))
        if self.box.duo and self.stage == 0:
            if list(responses) != [self.box.pw]:
                if self.box.strict: threading.Timer(0.05, self.t.close).start()
                return paramiko.AUTH_FAILED
            self.stage = 1
            if self.box.duo == "autopush":
                time.sleep(1.5); return paramiko.AUTH_SUCCESSFUL                       # waits while the push is approved
            return paramiko.server.InteractiveQuery("", "", (DUO_MENU, True))
        if self.box.duo:
            if list(responses) == ["1"]: time.sleep(0.5); return paramiko.AUTH_SUCCESSFUL
            if self.box.strict: threading.Timer(0.05, self.t.close).start()
            return paramiko.AUTH_FAILED
        if list(responses) == [want]: return paramiko.AUTH_SUCCESSFUL
        if self.box.strict: threading.Timer(0.05, self.t.close).start()
        return paramiko.AUTH_FAILED
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED
    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if destination[1] in self.box.refuse: return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.pending.append(destination); return paramiko.OPEN_SUCCEEDED

class SshBox(Server):
    """An SSH server: `first` says what it takes first, `pw` a password (then the code), `code` the one-time code."""
    def __init__(self, code="482913", pw=None, first="keyboard-interactive", prompt="Verification code: ", refuse=(), keys=(),
                 strict=False, hangup=False, duo=False):
        self.code, self.pw, self.first, self.prompt, self.refuse, self.keys = code, pw, first, prompt, set(refuse), set(keys)
        self.strict, self.hangup = strict, hangup                  # hang up after a wrong answer / as soon as sign-in starts
        self.duo = duo                                             # True: password then Duo's menu; "autopush": password, then wait
        super().__init__()
    def handle(self, c):
        t = paramiko.Transport(c); t.add_server_key(HOSTKEY); srv = Auth(self); srv.t = t; t.start_server(server=srv)
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
check("its local end is SOCKS5 with no sign-in of its own, like PuTTY's dynamic port", got == b"\x05\x00", got)
s = socket.create_connection(("127.0.0.1", t.port), 3); s.sendall(b"\x05\x01\x02"); s.recv(2); s.sendall(b"\x01\x03any\x03any"); got = s.recv(2); s.close()
check("a client set up with a user name is let in too", got == b"\x01\x00", got)
check("and it listens on this computer only", t.listener.getsockname()[0] == "127.0.0.1")
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
url6 = proxy.effective(c6).url()
kw = {"proxies": {"http": url6, "https": url6}}
r = requests.get(f"http://127.0.0.1:{web.server_address[1]}/x", timeout=8, **kw)
check("an address for web requests is the tunnel's local end", url6 == f"socks5h://127.0.0.1:{tunnel.get(c6, connect=False).port}", url6)
check("and a request through it arrives", r.text == "via-ssh" and hits == ["/x"] and ("channel", "127.0.0.1", web.server_address[1]) in box6.log, (r.text, hits))
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

print("== the Settings page: a Proxy section and an SSH Tunnel section")
import json, types
import ui.settings_pages.network as N
def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
box8 = SshBox(); LP = free_port()
db.set_setting("proxy", dict(proxy.DEFAULTS)); db.set_setting("ssh_tunnel", dict(tunnel.DEFAULTS))
page = N.ProxyPage(); page.load()
check("the page has the two sections", page.proxy_box.title() == "Proxy" and page.tunnel_box.title() == "SSH Tunnel")
check("the proxy types are HTTP, SOCKS5 and SOCKS4 (the tunnel is not one of them any more)",
      [page.kind.itemData(i) for i in range(page.kind.count())] == ["http", "socks5", "socks4"])
check("the tunnel is off to begin with, its fields greyed, port 22 and local port 1080",
      not page.t_enabled.isChecked() and not page.t_host.isEnabled() and page.t_port.value() == 22 and page.t_local.value() == 1080)
page.t_enabled.setChecked(True)
check("ticking it opens the fields", page.t_host.isEnabled() and page.t_local.isEnabled() and page.t_connect.isEnabled())
check("an empty server is refused on save", any("SSH Tunnel: enter the SSH server" in m for m in page.validate()), page.validate())
page.t_host.setText("127.0.0.1"); page.t_port.setValue(box8.port); page.t_user.setText("joe"); page.t_password.setText("s3cret"); page.t_local.setValue(LP)
page.t_use.click()
check("'Use it for the proxy above' points the proxy at SOCKS5 127.0.0.1 and the local port",
      page.mode.currentData() == "manual" and page.kind.currentData() == "socks5" and page.host.text() == "127.0.0.1" and page.port.value() == LP
      and page.user.text() == "" and "Save to keep it" in page.test_out.text())
check("and nothing is wrong with it", page.validate() == [], page.validate())
page.save()
saved_t = db.get_setting("ssh_tunnel")
check("saved: the tunnel in its own setting, its password only in Credential Manager",
      saved_t["host"] == "127.0.0.1" and saved_t["local_port"] == LP and saved_t["enabled"] and saved_t["otp"] == "ask"
      and STORE.get(("netcheck", tunnel.SECRET)) == "s3cret" and "s3cret" not in json.dumps(saved_t), saved_t)
check("and the proxy as SOCKS5 to it", proxy.settings()["kind"] == "socks5" and proxy.settings()["port"] == LP and proxy.settings()["host"] == "127.0.0.1")
check("the page says it is not connected yet", "Not connected" in page.t_status.text() and page.t_connect.isEnabled() and not page.t_disconnect.isEnabled())
answers[:] = ["482913"]; asked.clear()
page.test_to.setText(f"127.0.0.1:{echo.port}"); page.test()
check("Test through the proxy signs in to the tunnel first, then connects through it", page.test_out.text().startswith("OK:") and len(asked) == 1
      and tunnel.is_open(), (page.test_out.text(), asked))
check("the tunnel listens on the chosen local port, and the page says so", tunnel.status()["port"] == LP
      and f"SOCKS5 is on 127.0.0.1:{LP}" in page.t_status.text() and page.t_disconnect.isEnabled(), page.t_status.text())
s = socket.create_connection(("127.0.0.1", LP), 3); s.sendall(b"\x05\x01\x00"); got = s.recv(2); s.close()
check("so 127.0.0.1:port works as a plain SOCKS5 proxy, as PuTTY's does", got == b"\x05\x00", got)
page.save()
check("saving with nothing changed keeps it open", tunnel.is_open())
page.disconnect_tunnel()
check("Disconnect closes it and says so", not tunnel.is_open() and "Disconnected" in page.t_status.text())
answers[:] = ["482913"]; asked.clear(); page.connect_tunnel()
check("Connect signs in again", tunnel.is_open() and len(asked) == 1 and "Connected to" in page.t_status.text(), page.t_status.text())
page.t_host.setText("localhost"); page.save()
check("saving a different server closes it", not tunnel.is_open())
page.t_host.setText("127.0.0.1"); page.save()
blocker = socket.socket(); blocker.bind(("127.0.0.1", LP)); blocker.listen(1)
asked.clear(); page.connect_tunnel()
check("a local port already in use (PuTTY open on it) is said so, before anyone is asked for a code",
      not tunnel.is_open() and "already in use" in page.t_status.text() and not asked, page.t_status.text())
blocker.close()

print("== SOCKS5 to the tunnel's port, from anywhere in Toner")
c_sock = proxy.Config("socks5", "127.0.0.1", LP)
tunnel.close_all(); answers[:] = ["482913"]; asked.clear()
good, msg = reach(c_sock)
check("a connection through SOCKS5 127.0.0.1:port signs in to the tunnel first", good and len(asked) == 1 and tunnel.is_open(), (msg, asked))
check("its probe says it answers", proxy.probe(c_sock)[0] is True)
url = proxy.requests_kwargs({"name": "x", "host": "10.9.9.9"})["proxies"]["https"]
check("web requests use it as SOCKS5", url == f"socks5h://127.0.0.1:{LP}", url)
dev_own = {"name": "branch", "host": "127.0.0.1", "proxy": json.dumps({"mode": "custom", "kind": "socks5", "host": "127.0.0.1", "port": LP, "username": ""})}
good, msg = reach(proxy.for_device(dev_own))
check("a device whose own proxy points at it goes through it", good)
tunnel.close_all()
p = proxy.probe(c_sock)
check("closed, its probe says the tunnel is not open (rather than 'did not answer')", p[0] is False and "is not open" in p[1], p)
db.set_setting("ssh_tunnel", {**tunnel.settings(), "enabled": False})
good, msg = reach(c_sock)
check("with the tunnel turned off, nothing signs in and the port is simply not there", not good and "could not reach the proxy" in msg and len(asked) == 1, msg)
db.set_setting("ssh_tunnel", {**tunnel.settings(), "enabled": True})

print("== the indicator along the bottom")
from ui.statusstrip import StatusStrip
strip = StatusStrip(types.SimpleNamespace())
tunnel.close_all(); answers[:] = []; strip.restyle()
check("a tunnel that is set up but not open is 'disconnected', and says to click", "Proxy disconnected" in strip.proxy.text()
      and "Click to sign in" in strip.proxy.toolTip(), (strip.proxy.text(), strip.proxy.toolTip()))
answers[:] = ["482913"]; asked.clear()
strip._proxy_clicked()
check("clicking shows that it is signing in", "signing in" in strip.proxy.text())
end = time.time() + 15
while strip.opening and time.time() < end: app.processEvents(); time.sleep(0.02)
app.processEvents()
check("then it is connected, and says where SOCKS5 is", "Proxy connected" in strip.proxy.text() and f"127.0.0.1:{LP}" in strip.proxy.toolTip()
      and len(asked) == 1, (strip.proxy.text(), strip.proxy.toolTip(), asked))
seen = []; strip.navigate.connect(lambda a, b: seen.append((a, b))); strip._proxy_clicked()
check("clicking it when it is open opens Settings > Proxy", seen == [("Settings", "Proxy")])
tunnel.close_all(); proxy.set_code_prompt(lambda *a, **k: "000000")
strip.connect_tunnel()
end = time.time() + 15
while strip.opening and time.time() < end: app.processEvents(); time.sleep(0.02)
app.processEvents()
check("a sign-in that fails says why in the tooltip", "Proxy disconnected" in strip.proxy.text() and "rejected the sign-in" in strip.proxy.toolTip(), strip.proxy.toolTip())
proxy.set_code_prompt(hook)
db.set_setting("ssh_tunnel", {**tunnel.settings(), "enabled": False}); strip.restyle()
check("with the tunnel turned off, the indicator is about the proxy again", "Click to sign in" not in strip.proxy.toolTip())
db.set_setting("ssh_tunnel", {**tunnel.settings(), "enabled": True})
tunnel.close_all()

print("== the device's own proxy")
from ui.inventory import DeviceDialog
dd = DeviceDialog()
dd.proxy_mode.setCurrentIndex(dd.proxy_mode.findData("custom"))
check("a device's proxy types do not include the tunnel; it uses SOCKS5 127.0.0.1:1080 instead", dd.proxy_kind.findData("tunnel") < 0)
def devrow(name, own):
    return dict(name=name, vendor="cisco", host="10.3.3.3", port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0,
                enabled=1, location="", details="", folder_id=None, tags="", fields="", proxy=json.dumps(own))
db.save_device(devrow("legacy1", {"mode": "custom", "kind": "tunnel", "host": "b.example.com", "port": 22, "username": "jw", "otp": "ask"}))
legacy = next(d for d in db.list_devices() if d["name"] == "legacy1")
dl = DeviceDialog(legacy)
check("a device saved with the old tunnel type opens as SOCKS5 to the tunnel's port",
      dl.proxy_kind.currentData() == "socks5" and dl.proxy_host.text() == "127.0.0.1" and dl.proxy_port.value() == LP
      and dl.proxy_otp.currentData() == "", (dl.proxy_kind.currentData(), dl.proxy_host.text(), dl.proxy_port.value()))

print("== moving 1.5.2-1.5.5 settings over")
db.set_setting("ssh_tunnel", dict(tunnel.DEFAULTS))
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "tunnel", "host": "bastion.example.com", "port": 2222, "username": "jw",
                         "otp": "ask", "key_file": ""})
STORE[("netcheck", proxy.GLOBAL_SECRET)] = "pw1"
moved = tunnel.migrate()
ts = tunnel.settings()
check("a proxy set to the old tunnel type becomes the SSH Tunnel section, with its password",
      moved and ts["enabled"] and ts["host"] == "bastion.example.com" and ts["port"] == 2222 and ts["username"] == "jw" and ts["otp"] == "ask"
      and STORE.get(("netcheck", tunnel.SECRET)) == "pw1" and ("netcheck", proxy.GLOBAL_SECRET) not in STORE, (ts, STORE))
ps = proxy.settings()
check("and the proxy becomes SOCKS5 127.0.0.1:1080", ps["mode"] == "manual" and ps["kind"] == "socks5" and ps["host"] == "127.0.0.1" and ps["port"] == 1080, ps)
legacy = next(d for d in db.list_devices() if d["name"] == "legacy1")
check("a device with the old type now points at the tunnel's port", proxy.device_settings(legacy) == {"mode": "custom", "kind": "socks5",
      "host": "127.0.0.1", "port": 1080, "username": ""}, proxy.device_settings(legacy))
check("a second run changes nothing", tunnel.migrate() is False)
db.delete_device(legacy["id"])
db.set_setting("ssh_tunnel", dict(tunnel.DEFAULTS)); db.set_setting("proxy", dict(proxy.DEFAULTS)); STORE.pop(("netcheck", tunnel.SECRET), None)

print("== signing in with a key file")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
KEYDIR = os.path.join(SP, "keys%d" % int(time.time())); os.makedirs(KEYDIR)
def make_key(name, passphrase=None):
    k = ed25519.Ed25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    path = os.path.join(KEYDIR, name)
    with open(path, "wb") as f: f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc))
    return path, paramiko.PKey.from_path(path, password=passphrase.encode() if passphrase else None).get_base64()
plain_path, plain_pub = make_key("id_plain")
locked_path, locked_pub = make_key("id_locked", "keypass")
other_path, other_pub = make_key("id_other")
proxy.set_code_prompt(hook)

kb1 = SshBox(code=None, first="publickey", keys=[plain_pub])
answers[:] = []; asked.clear()
good, msg = reach(cfg_for(kb1, key_file=plain_path))
check("a key the server knows signs in with nothing asked", good and not asked and ("publickey", "joe", plain_pub) in kb1.log, (msg, asked, kb1.log))
check("and no password is sent", not [l for l in kb1.log if l[0] == "password"])
tunnel.close_all()

kb2 = SshBox(first="publickey", keys=[plain_pub])
answers[:] = ["482913"]; asked.clear()
good, msg = reach(cfg_for(kb2, key_file=plain_path, otp="ask"))
check("a server that wants the key and then a code gets both, with only the code asked", good and len(asked) == 1 and asked[0][0] == "One-time code", (msg, asked))
tunnel.close_all()

kb3 = SshBox(code=None, first="publickey", keys=[locked_pub])
answers[:] = []; asked.clear()
good, msg = reach(cfg_for(kb3, key_file=locked_path, password="keypass"))
check("a protected key opens with the saved password as its passphrase", good and not asked and not [l for l in kb3.log if l[0] == "password"], (msg, asked, kb3.log))
tunnel.close_all()
answers[:] = ["keypass"]; asked.clear()
good, msg = reach(cfg_for(kb3, key_file=locked_path))
check("with no password saved, the passphrase is asked for, hidden", good and len(asked) == 1 and asked[0][0] == "Key passphrase" and asked[0][2] is True, (msg, asked))
tunnel.close_all()
answers[:] = ["keypass"]; asked.clear()
good, msg = reach(cfg_for(kb3, key_file=locked_path, password="not-it"))
check("a saved password that is not the passphrase leads to the question, which says so", good and "not its passphrase" in asked[0][1], (msg, asked))
tunnel.close_all()
answers[:] = ["wrong"]; asked.clear()
good, msg = reach(cfg_for(kb3, key_file=locked_path))
check("a wrong passphrase is explained", not good and "wrong passphrase for the key file id_locked" in msg, msg)
answers[:] = [""]
good, msg = reach(cfg_for(kb3, key_file=locked_path))
check("cancelling the passphrase box says so", not good and "no passphrase was entered" in msg, msg)

kb4 = SshBox(code=None, first="publickey", keys=[plain_pub])
good, msg = reach(cfg_for(kb4, key_file=other_path))
check("a key the server does not know is explained", not good and "did not accept the key file" in msg and "authorized_keys" in msg, msg)
kb5 = SshBox(first="publickey,keyboard-interactive", keys=[plain_pub])
answers[:] = ["482913"]; asked.clear()
good, msg = reach(cfg_for(kb5, key_file=other_path, otp="ask"))
check("when the key is refused but the server also takes a code, the code is asked for and works", good and len(asked) == 1, (msg, asked))
tunnel.close_all()

good, msg = reach(cfg_for(kb1, key_file=os.path.join(KEYDIR, "missing")))
check("a missing key file is explained", not good and "was not found" in msg, msg)
ppk = os.path.join(KEYDIR, "putty.ppk")
with open(ppk, "w") as f: f.write("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n")
good, msg = reach(cfg_for(kb1, key_file=ppk))
check("a PuTTY key says how to convert it", not good and "PuTTYgen" in msg and "Export OpenSSH key" in msg, msg)
junk = os.path.join(KEYDIR, "notakey.txt")
with open(junk, "w") as f: f.write("hello")
good, msg = reach(cfg_for(kb1, key_file=junk))
check("a file that is not a key is explained", not good and "not a private key Toner can read" in msg, msg)

print("== the key file in the SSH Tunnel section")
db.set_setting("ssh_tunnel", dict(tunnel.DEFAULTS)); STORE.pop(("netcheck", tunnel.SECRET), None)
page = N.ProxyPage(); page.load(); page.t_enabled.setChecked(True)
page.t_host.setText("127.0.0.1"); page.t_port.setValue(kb1.port); page.t_user.setText("joe"); page.t_local.setValue(free_port())
check("without a key file the password box is the server's password", "PuTTY" in page.t_password.placeholderText(), page.t_password.placeholderText())
page.t_key.setText(os.path.join(KEYDIR, "missing"))
check("a key file that is not there is refused on save", any("was not found" in m for m in page.validate()), page.validate())
page.t_key.setText(plain_path)
check("a real one passes, and the password box becomes its passphrase", page.validate() == [] and "passphrase" in page.t_password.placeholderText())
page.save()
check("it is saved with the tunnel", tunnel.settings()["key_file"] == plain_path and tunnel.config().key_file == plain_path)
asked.clear(); page.connect_tunnel()
check("Connect signs in with it, with nothing asked", tunnel.is_open() and not asked, page.t_status.text())
page.save()
check("saving with nothing changed keeps it open", tunnel.is_open())
page.t_key.setText(other_path); page.save()
check("choosing another key file closes it", not tunnel.is_open())
check("a key file is ignored for the proxy types", proxy._config({"kind": "socks5", "host": "h", "port": 1, "key_file": plain_path}, "").key_file == "")
tunnel.close_all()

print("== a server that hangs up after a wrong answer (\"No existing session\")")
proxy.set_code_prompt(hook); proxy.WAIT_HOOK = None
st1 = SshBox(strict=True); cs1 = cfg_for(st1, password="s3cret", otp="ask")
answers[:] = ["482913"]; asked.clear()
good, msg = reach(cs1)
check("a saved password is never typed into the code question", good and not any(l[0] == "answer" and "s3cret" in l[1] for l in st1.log), (msg, st1.log))
check("the server is asked which ways it takes first, and the code is asked for once", st1.log[0][0] == "none" and len(asked) == 1, (st1.log, asked))
tunnel.close_all()
st2 = SshBox(strict=True); answers[:] = ["000000"]
good, msg = reach(cfg_for(st2, otp="ask"))
check("a wrong code on such a server is reported plainly, not as 'No existing session'", not good and "No existing session" not in msg
      and ("rejected the sign-in" in msg or "closed the connection after the answers were sent" in msg), msg)
st3 = SshBox(hangup=True); answers[:] = ["482913"]
good, msg = reach(cfg_for(st3, otp="ask"))
check("a server that hangs up as the sign-in starts says so", not good and "No existing session" not in msg and "closed the connection" in msg, msg)
tunnel.close_all()

print("== a server that stops before the sign-in (\"No existing session\" from the key exchange)")
class Stall(Server):
    """Sends an SSH banner and then nothing: the key exchange never finishes."""
    def handle(self, c):
        c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"); time.sleep(8); c.close()
class AfterKex(Server):
    """Finishes the key exchange and hangs up straight away."""
    def handle(self, c):
        t = paramiko.Transport(c); t.add_server_key(HOSTKEY); ev = threading.Event()
        t.start_server(event=ev, server=paramiko.ServerInterface()); ev.wait(5); t.close()
st5 = Stall(); tun5 = tunnel.Tunnel(cfg_for(st5, otp="ask"))
try: tun5.open(timeout=2); m5 = ""
except proxy.ProxyError as e: m5 = str(e)
check("a key exchange that never finishes is said to be that, not 'No existing session'", "did not finish the SSH key exchange within 2 seconds" in m5
      and "never got as far as sending the user name" in m5 and "No existing session" not in m5, m5)
check("and the error says where the steps were written", str(tunnel.log_path()) in m5, m5)
log5 = tunnel.log_path().read_text(encoding="utf-8")
check("the log names the server, the version and what happened", f"127.0.0.1:{st5.port} as joe" in log5 and "TONER: failed" in log5 and "key exchange" in log5, log5[-400:])
st6 = AfterKex(); tun6 = tunnel.Tunnel(cfg_for(st6, otp="ask"))
try: tun6.open(timeout=5); m6 = ""
except proxy.ProxyError as e: m6 = str(e)
check("a server that hangs up after the key exchange says so", ("closed the connection during the SSH key exchange" in m6 or "closed the connection before Toner could sign in" in m6)
      and "No existing session" not in m6, m6)
st7 = SshBox(pw="s3cret", first="password"); answers[:] = ["482913"]
good, msg = reach(cfg_for(st7, password="s3cret", otp="ask"))
log7 = tunnel.log_path().read_text(encoding="utf-8")
check("a good sign-in is logged step by step: what the server takes, what was tried, what it asked", good and "the server takes: password" in log7
      and "trying password" in log7 and "password accepted; the server also wants: keyboard-interactive" in log7 and "'Verification code: '" in log7, log7[-800:])
check("the log has the SSH library's own steps too (algorithms agreed)", "Kex" in log7 or "kex" in log7, log7[:600])
check("and never the password or the code", "s3cret" not in log7 and "482913" not in log7)
tunnel.close_all()

print("== domain password and Duo, as in the PuTTY instructions")
proxy.set_code_prompt(hook); proxy.WAIT_HOOK = None
d1 = SshBox(duo=True, pw="Domain#pw", strict=True); answers[:] = ["1"]; asked.clear()
good, msg = reach(cfg_for(d1, password="Domain#pw", otp="ask"))
answers_sent = [l[1] for l in d1.log if l[0] == "answer"]
check("the saved password answers 'Password:', and Duo's question is asked of you", good and answers_sent == [["Domain#pw"], ["1"]] and len(asked) == 1, (msg, answers_sent, asked))
check("the box shows Duo's own options and says to type 1 for a push", "1. Duo Push to XXX-XXX-1234" in asked[0][1] and "1 for Duo Push" in asked[0][1], asked[0][1] if asked else "")
check("the password is never typed into Duo's question", ["Domain#pw"] not in answers_sent[1:])
tunnel.close_all()
d2 = SshBox(duo="autopush", pw="Domain#pw", strict=True); answers[:] = []; asked.clear()
good, msg = reach(cfg_for(d2, password="Domain#pw", otp="ask"))
check("a server that sends the push by itself is simply waited for, with nothing asked", good and not asked, (msg, asked))
tunnel.close_all()
d3 = SshBox(duo=True, pw="Domain#pw", strict=True); answers[:] = ["Domain#pw", "1"]; asked.clear()
good, msg = reach(cfg_for(d3, otp="ask"))
check("with no saved password, it asks for the password (hidden), then Duo", good and [a[0] for a in asked] == ["Password", "One-time code"] and asked[0][2] is True, (msg, asked))
tunnel.close_all()

print("== the server from the log: OpenSSH that offers password and keyboard-interactive, with Duo in PAM")
d4 = SshBox(duo=True, pw="Domain#pw", first="password,keyboard-interactive"); answers[:] = ["1"]; asked.clear()
good, msg = reach(cfg_for(d4, password="Domain#pw", otp="ask"))
check("keyboard-interactive is used first, as PuTTY and ssh do, so Duo can ask its question", good and len(asked) == 1
      and not [l for l in d4.log if l[0] == "password"], (msg, d4.log, asked))
log4 = tunnel.log_path().read_text(encoding="utf-8")
check("the log shows that order", log4.index("trying keyboard-interactive") < log4.index("keyboard-interactive accepted") and "trying password" not in log4)
tunnel.close_all()
d5 = SshBox(code="s3cret", pw="s3cret", first="password,keyboard-interactive", prompt="Password: ")   # its question is the password
answers[:] = []; asked.clear()
good, msg = reach(cfg_for(d5, password="s3cret", otp="ask"))
check("a plain server's 'Password:' question is answered with the saved password, nothing asked", good and not asked, (msg, asked))
tunnel.close_all()
d6 = SshBox(code="999999", pw="s3cret", first="password,keyboard-interactive", prompt="Verification code: ")
answers[:] = ["000000"]; asked.clear()
good, msg = reach(cfg_for(d6, password="s3cret", otp="ask"))
check("a wrong answer to the question is not followed by more tries", not good and "rejected the sign-in" in msg and len(asked) == 1, (msg, asked))
d7 = SshBox(duo=True, pw="Domain#pw", first="password,keyboard-interactive")
good, msg = reach(proxy.Config("tunnel", "127.0.0.1", d7.port, "jwetlesen@sentinel.com", "wrong", otp="ask"))
check("a refused sign-in with an e-mail style user name suggests checking it", not good and "Check the user name" in msg and "jwetlesen@sentinel.com" in msg, msg)
tunnel.close_all()

print("== the Test and Connect buttons, with the real question box")
from ui import otpprompt
shown = []
class CodeDialog:
    def __init__(self, parent=None): pass
    def setWindowTitle(self, t): shown.append(t)
    def setLabelText(self, t): pass
    def setTextEchoMode(self, m): pass
    def setWindowFlag(self, *a): pass
    def exec(self): return 1
    def textValue(self): return "482913"
real_dialog = otpprompt.QInputDialog
otpprompt.QInputDialog = CodeDialog
otpprompt.install()
st4 = SshBox(strict=True); LP4 = free_port()
db.set_setting("ssh_tunnel", {**tunnel.DEFAULTS, "enabled": True, "host": "127.0.0.1", "port": st4.port, "username": "joe", "otp": "ask", "local_port": LP4})
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "socks5", "host": "127.0.0.1", "port": LP4})
STORE[("netcheck", tunnel.SECRET)] = "s3cret"
page4 = N.ProxyPage(); page4.load(); page4.test_to.setText(f"127.0.0.1:{echo.port}")
t0 = time.time(); page4.test(); took = time.time() - t0
check("Test, clicked on the window's own thread: the code box still appears and the sign-in works",
      page4.test_out.text().startswith("OK:") and shown == ["One-time code"], (page4.test_out.text(), shown))
check("without waiting for a time-out", took < 20, took)
page4.disconnect_tunnel(); shown.clear()
page4.connect_tunnel()
check("Connect does the same", tunnel.is_open() and shown == ["One-time code"] and "Connected to" in page4.t_status.text(), (shown, page4.t_status.text()))
otpprompt.QInputDialog = real_dialog
STORE.pop(("netcheck", tunnel.SECRET), None)
tunnel.close_all()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
