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
    def check_auth_publickey(self, u, key):
        self.box.log.append(("publickey", u, key.get_base64()))
        if "publickey" in self.now and key.get_base64() in self.box.keys:
            if self.box.code is None: return paramiko.AUTH_SUCCESSFUL
            self.now = "keyboard-interactive"; return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_auth_interactive(self, u, sub):
        if "keyboard-interactive" not in self.now: return paramiko.AUTH_FAILED          # what a real server does
        return paramiko.server.InteractiveQuery("", "", (self.box.prompt, False))
    def check_auth_none(self, u):
        self.box.log.append(("none", u))
        if self.box.hangup: threading.Timer(0, self.t.close).start(); time.sleep(0.5)     # gone before it answers
        return paramiko.AUTH_FAILED
    def check_auth_interactive_response(self, responses):
        want = self.box.code() if callable(self.box.code) else self.box.code
        self.box.log.append(("answer", list(responses)))
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
                 strict=False, hangup=False):
        self.code, self.pw, self.first, self.prompt, self.refuse, self.keys = code, pw, first, prompt, set(refuse), set(keys)
        self.strict, self.hangup = strict, hangup                  # hang up after a wrong answer / as soon as sign-in starts
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
check("the key file row shows only for a tunnel", dd.access.isRowVisible(dd.proxy_key_row) and
      (dd.proxy_kind.setCurrentIndex(dd.proxy_kind.findData("socks5")), not dd.access.isRowVisible(dd.proxy_key_row))[1])
dd.proxy_kind.setCurrentIndex(dd.proxy_kind.findData("tunnel")); dd.proxy_key.setText(r"C:\keys\id_ed25519")
check("a device keeps its key file path with its proxy", dd.values()["proxy"]["key_file"] == r"C:\keys\id_ed25519")
dd.proxy_kind.setCurrentIndex(dd.proxy_kind.findData("socks5"))
check("but not for another type", "key_file" not in dd.values()["proxy"])

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

print("== the key file in Settings")
db.set_setting("proxy", dict(proxy.DEFAULTS))
page = N.ProxyPage(); page.load()
page.mode.setCurrentIndex(page.mode.findData("manual")); page.kind.setCurrentIndex(page.kind.findData("socks5")); page.adapt()
check("the key file row is hidden for other types", not page.form.isRowVisible(page.key_row))
page.kind.setCurrentIndex(page.kind.findData("tunnel"))
check("and shown for a tunnel, its note only once a file is chosen", page.form.isRowVisible(page.key_row) and not page.form.isRowVisible(page.key_note))
page.key_file.setText(os.path.join(KEYDIR, "missing")); page.host.setText("127.0.0.1"); page.port.setValue(kb1.port); page.user.setText("joe")
check("a key file that is not there is refused on save", any("was not found" in m for m in page.validate()), page.validate())
page.key_file.setText(plain_path)
check("a real one passes, and the note says the password is its passphrase",
      page.validate() == [] and page.form.isRowVisible(page.key_note) and "passphrase" in page.password.placeholderText())
page.save()
check("it is saved with the proxy setting", proxy.settings()["key_file"] == plain_path and proxy.global_config(full=True).key_file == plain_path)
page.test_to.setText(f"127.0.0.1:{echo.port}"); asked.clear(); page.test()
check("the Test button signs in with it", page.test_out.text().startswith("OK:") and not asked, page.test_out.text())
gc = proxy.global_config()
check("the tunnel stays open", tunnel.is_open(gc))
page.save()
check("saving with nothing changed keeps it open", tunnel.is_open(gc))
page.key_file.setText(other_path); page.save()
check("choosing another key file closes it", not tunnel.is_open(gc))
check("a key file is ignored for the other types", proxy._config({"kind": "socks5", "host": "h", "port": 1, "key_file": plain_path}, "").key_file == "")
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

print("== the Test button, with the real question box")
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
st4 = SshBox(strict=True)
db.set_setting("proxy", {**proxy.DEFAULTS, "mode": "manual", "kind": "tunnel", "host": "127.0.0.1", "port": st4.port, "username": "joe", "otp": "ask"})
STORE[("netcheck", proxy.GLOBAL_SECRET)] = "s3cret"
page4 = N.ProxyPage(); page4.load(); page4.test_to.setText(f"127.0.0.1:{echo.port}")
t0 = time.time(); page4.test(); took = time.time() - t0
check("clicked on the window's own thread, the code box still appears and the sign-in works", page4.test_out.text().startswith("OK:") and shown == ["One-time code"], (page4.test_out.text(), shown))
check("without waiting for a time-out", took < 20, took)
otpprompt.QInputDialog = real_dialog
STORE.pop(("netcheck", proxy.GLOBAL_SECRET), None)
tunnel.close_all()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
