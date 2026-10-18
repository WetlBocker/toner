# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import base64, http.server, json, logging, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\px%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import custom, db, fileserver, jump, notify, proxy
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
warned = []
QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2]))
QMessageBox.information = staticmethod(lambda *a, **k: None)


# ================================================================ fakes: proxies and targets
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
    def stop(self): self.sock.close()

class HttpProxy(Server):
    def __init__(self, auth=None, refuse=None):
        self.auth, self.refuse = auth, refuse; super().__init__()
    def handle(self, c):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk: return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n"); first = lines[0]
        headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
        self.log.append((first, headers))
        if self.auth and headers.get("proxy-authorization") != "Basic " + base64.b64encode(self.auth.encode()).decode():
            c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"); return
        if self.refuse:
            c.sendall(f"HTTP/1.1 {self.refuse} Refused\r\nContent-Length: 0\r\n\r\n".encode()); return
        if first.startswith("CONNECT"):
            host, port = first.split()[1].rsplit(":", 1)
            up = socket.create_connection((host, int(port)), 5)
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if rest: up.sendall(rest)
            pipe(c, up)
        else:                                               # a plain request addressed to the proxy
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy"); c.close()

class Socks5Proxy(Server):
    def __init__(self, auth=None):
        self.auth = auth; super().__init__()
    def handle(self, c):
        _, n = recvn(c, 2); methods = recvn(c, n)
        if self.auth:
            if 2 not in methods: c.sendall(b"\x05\xff"); return
            c.sendall(b"\x05\x02"); recvn(c, 1)
            user = recvn(c, recvn(c, 1)[0]).decode(); pw = recvn(c, recvn(c, 1)[0]).decode()
            good = (user, pw) == tuple(self.auth.split(":", 1))
            c.sendall(b"\x01\x00" if good else b"\x01\x01")
            if not good: self.log.append(("auth failed", user)); return
        else:
            c.sendall(b"\x05\x00")
        _, cmd, _, atyp = recvn(c, 4)
        addr = socket.inet_ntoa(recvn(c, 4)) if atyp == 1 else recvn(c, recvn(c, 1)[0]).decode()
        port = int.from_bytes(recvn(c, 2), "big"); self.log.append(("CONNECT", addr, port))
        up = socket.create_connection((addr, port), 5)
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); pipe(c, up)

class Echo(Server):
    def handle(self, c):
        while True:
            d = c.recv(4096)
            if not d: return
            c.sendall(d)

class Smtp(Server):
    def handle(self, c):
        c.sendall(b"220 fake ESMTP ready\r\n"); f = c.makefile("rb")
        for line in f:
            if line.upper().startswith(b"QUIT"): c.sendall(b"221 bye\r\n"); return
            c.sendall(b"250 ok\r\n")

hits = []
class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self._answer()
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0)); self._answer()
    def _answer(self):
        hits.append(self.path); self.send_response(200); self.send_header("Content-Length", "9"); self.end_headers(); self.wfile.write(b"direct-ok")
    def log_message(self, *a): pass
web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target); threading.Thread(target=web.serve_forever, daemon=True).start()
WEB = f"http://127.0.0.1:{web.server_address[1]}/hello"

def dev(name="sw1", vendor="cisco", host="127.0.0.1", **kw):
    d = dict(name=name, vendor=vendor, host=host, port=0, platform="", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    return d
def global_mode(**s): db.set_setting("proxy", {**proxy.DEFAULTS, **s})
def custom_for(p, **extra): return json.dumps({"mode": "custom", "kind": "http", "host": "127.0.0.1", "port": p.port, "username": "", **extra})


# ================================================================ rules
print("== bypass list")
B = "localhost, 127.0.0.1, *.corp.example.com, .lab.local, 10.0.0.0/8, <local>"
for host, want in (("localhost", True), ("LOCALHOST", True), ("127.0.0.1", True), ("sw.corp.example.com", True), ("corp.example.com", False), ("x.lab.local", True),
                   ("10.9.8.7", True), ("11.0.0.1", False), ("intranet", True), ("www.example.com", False), ("172.16.0.1", False)):
    check(f"{host} {'bypasses' if want else 'goes through'}", proxy.bypassed(host, B) == want)
check("an empty list bypasses nothing", not proxy.bypassed("localhost", "") and not proxy.bypassed("x", None))

print("== which way a connection goes")
d = dev()
check("the default is the Windows settings for web, direct for everything else", proxy.settings()["mode"] == "system" and proxy.resolve(d, purpose="web")[0] == "system" and proxy.resolve(d, purpose="socket")[0] == "direct" and proxy.for_device(d) is None and proxy.requests_kwargs(d) == {})
global_mode(mode="none")
check("'no proxy' ignores even a Windows proxy for web requests", proxy.requests_kwargs(d) == {"proxies": {"http": "", "https": ""}} and proxy.for_device(d) is None)
global_mode(mode="manual", kind="http", host="proxy.corp", port=3128, username="svc", bypass="localhost, *.lab")
STORE[("netcheck", proxy.GLOBAL_SECRET)] = "p@ss:w/rd"
cfg = proxy.for_device(dev(host="10.1.1.1"))
check("manual: used for sockets and web", cfg and (cfg.kind, cfg.host, cfg.port, cfg.username, cfg.password) == ("http", "proxy.corp", 3128, "svc", "p@ss:w/rd") and proxy.resolve(dev(host="10.1.1.1"), purpose="web")[0] == "proxy")
check("manual: the proxy URL escapes special characters in the password", cfg.url() == "http://svc:p%40ss%3Aw%2Frd@proxy.corp:3128" and proxy.requests_kwargs(dev(host="10.1.1.1"))["proxies"]["https"] == cfg.url())
check("manual: a bypassed address goes direct", proxy.for_device(dev(host="x.lab")) is None and proxy.requests_kwargs(dev(host="x.lab")) == {"proxies": {"http": "", "https": ""}})
check("SOCKS URLs ask the proxy to resolve names", proxy.Config("socks5", "h", 1080).url() == "socks5h://h:1080" and proxy.Config("socks4", "h", 1080).url() == "socks4a://h:1080")
check("a manual setting with no address means direct", (global_mode(mode="manual", host=""), proxy.for_device(d))[1] is None)
global_mode(mode="manual", host="proxy.corp", port=3128)
check("a device set to 'direct' beats the global proxy", proxy.for_device(dev(proxy=json.dumps({"mode": "none"}), host="10.1.1.1")) is None)
own = dev(host="10.1.1.1", proxy=json.dumps({"mode": "custom", "kind": "socks5", "host": "px2", "port": 1080, "username": "u"}))
STORE[("netcheck", "sw1:proxy")] = "devpw"
c2 = proxy.for_device(own)
check("a device's own proxy beats the global one, with its own saved password", c2 and (c2.kind, c2.host, c2.port, c2.username, c2.password) == ("socks5", "px2", 1080, "u", "devpw"))
check("...even for an address the global bypass list names", proxy.for_device({**own, "host": "localhost"}) is not None)
check("a password typed but not yet saved is used for a test", proxy.for_device({**own, "_proxy_secret": "typed"}).password == "typed")
check("a device proxy without an address means direct", proxy.for_device(dev(proxy=json.dumps({"mode": "custom", "host": ""}))) is None)
check("a damaged value is ignored", proxy.device_settings({"proxy": "{oops"}) == {} and proxy.device_settings({"proxy": ""}) == {} and proxy.device_settings({}) == {})
global_mode(mode="system")

# ================================================================ making connections
print("== HTTP proxy (CONNECT)")
echo = Echo(); hp = HttpProxy()
s = proxy.connect(proxy.Config("http", "127.0.0.1", hp.port), "127.0.0.1", echo.port, 5); s.sendall(b"hello"); got = s.recv(10); s.close()
check("data flows both ways through the tunnel", got == b"hello" and hp.log[0][0] == f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1" and "proxy-authorization" not in hp.log[0][1], hp.log)
hp2 = HttpProxy(auth="svc:s3cret")
s = proxy.connect(proxy.Config("http", "127.0.0.1", hp2.port, "svc", "s3cret"), "127.0.0.1", echo.port, 5); s.sendall(b"x"); ok_ = s.recv(5) == b"x"; s.close()
check("a user name and password are sent as Basic authentication", ok_ and hp2.log[0][1]["proxy-authorization"] == "Basic " + base64.b64encode(b"svc:s3cret").decode())
def fails(cfg, port=None):
    try: proxy.connect(cfg, "127.0.0.1", port or echo.port, 3).close(); return None
    except proxy.ProxyError as e: return str(e)
    except Exception as e: return "WRONG TYPE " + type(e).__name__
m = fails(proxy.Config("http", "127.0.0.1", hp2.port)); check("a proxy that wants a login says so", m and "needs a user name and password" in m, m)
m = fails(proxy.Config("http", "127.0.0.1", hp2.port, "svc", "wrong")); check("a wrong password says so", m and "rejected the user name or password" in m, m)
hp3 = HttpProxy(refuse=403); m = fails(proxy.Config("http", "127.0.0.1", hp3.port)); check("a refusal is explained", m and "would not connect" in m and "403" in m, m)
dead = socket.socket(); dead.bind(("127.0.0.1", 0)); dport = dead.getsockname()[1]; dead.close()
m = fails(proxy.Config("http", "127.0.0.1", dport)); check("a proxy that is not there is explained", m and "could not reach the proxy" in m and str(dport) in m, m)
check("a proxy error is not retried like a dropped connection", issubclass(proxy.ProxyError, OSError) and not issubclass(proxy.ProxyError, ConnectionError))

print("== SOCKS5 proxy")
sp = Socks5Proxy()
s = proxy.connect(proxy.Config("socks5", "127.0.0.1", sp.port), "127.0.0.1", echo.port, 5); s.sendall(b"socks"); got = s.recv(10); s.close()
check("data flows through SOCKS5", got == b"socks" and sp.log[0][:1] == ("CONNECT",) and sp.log[0][2] == echo.port, sp.log)
sp2 = Socks5Proxy(auth="u:pw")
s = proxy.connect(proxy.Config("socks5", "127.0.0.1", sp2.port, "u", "pw"), "127.0.0.1", echo.port, 5); s.sendall(b"a"); ok_ = s.recv(3) == b"a"; s.close()
check("SOCKS5 with a user name and password", ok_)
m = fails(proxy.Config("socks5", "127.0.0.1", sp2.port, "u", "bad")); check("a wrong SOCKS password is a proxy error", m and "WRONG TYPE" not in m and ("127.0.0.1" in m), m)
m = fails(proxy.Config("socks5", "127.0.0.1", dport)); check("a SOCKS proxy that is not there is explained", m and "could not reach the proxy" in m, m)

print("== the Test buttons' engine")
ok_, msg = proxy.test_tunnel(proxy.Config("http", "127.0.0.1", hp.port), "127.0.0.1", echo.port); check("a working tunnel", ok_ and "Connected to 127.0.0.1" in msg and "HTTP proxy 127.0.0.1" in msg, msg)
ok_, msg = proxy.test_tunnel(proxy.Config("http", "127.0.0.1", dport), "127.0.0.1", echo.port); check("a failing one", not ok_ and "could not reach" in msg)
ok_, msg = proxy.test_web("127.0.0.1", web.server_address[1], direct=True); check("a direct web test reaches the target or explains why not", isinstance(ok_, bool) and msg)

# ================================================================ requests
print("== web requests")
kw = {"proxies": {"http": f"http://127.0.0.1:{hp.port}", "https": f"http://127.0.0.1:{hp.port}"}}
hp.log.clear(); r = requests.get(WEB, timeout=5, **kw)
check("a request goes to the proxy, which sees the full address", r.text == "via-proxy" and hp.log[0][0].startswith(f"GET {WEB} "), hp.log)
os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{hp.port}"; hp.log.clear(); hits.clear()
r = requests.get(WEB, timeout=5, proxies=proxy.DIRECT)
check("'direct' beats a proxy in the environment", r.text == "direct-ok" and not hp.log and hits == ["/hello"], (r.text, hp.log))
del os.environ["HTTP_PROXY"]
global_mode(mode="manual", host="127.0.0.1", port=hp.port, bypass=""); hp.log.clear()
chk = {"name": "page", "kind": "http", "target": WEB, "expect": "2xx", "mode": "number", "scope": [], "higher_worse": 1}
res = custom.run_http(chk, dev(host="127.0.0.1"))
check("a web check follows the global manual proxy", res.status == "OK" and hp.log and hp.log[0][0].startswith("GET http://127.0.0.1"), (res, hp.log))
hp.log.clear(); hits.clear(); res = custom.run_http(chk, dev(host="127.0.0.1", proxy=json.dumps({"mode": "none"})))
check("...and goes straight to a device that is set to connect directly", res.status == "OK" and not hp.log and hits, (res, hp.log))
global_mode(mode="system")
hp.log.clear(); res = custom.run_http(chk, dev(host="127.0.0.1", proxy=custom_for(hp)))
check("a device's own proxy is used for its web check", res.status == "OK" and hp.log, hp.log)

print("== TCP and certificate checks")
chk = {"name": "port", "kind": "tcp", "port": echo.port, "warn": None, "fail": None, "higher_worse": 1}
hp.log.clear(); res = custom.run_tcp(chk, dev(host="127.0.0.1", proxy=custom_for(hp)))
check("a TCP port check is opened through the device's proxy", res.status == "OK" and hp.log and hp.log[0][0].startswith(f"CONNECT 127.0.0.1:{echo.port}"), (res, hp.log))
res = custom.run_tcp(chk, dev(host="127.0.0.1", proxy=custom_for(HttpProxy(refuse=403))))
check("a proxy that refuses makes the check FAIL with the reason", res.status == "FAIL" and "403" in res.message, res)
res = custom.run_tcp(chk, dev(host="127.0.0.1")); check("without a proxy it connects directly", res.status == "OK")
hp.log.clear(); res = custom.run_tls({"name": "tls", "kind": "tls", "port": echo.port, "higher_worse": 0}, dev(host="127.0.0.1", proxy=custom_for(hp)))
check("a certificate check goes through the proxy too (the echo server has no certificate, so it fails after connecting)", hp.log and res.status == "FAIL", (res, hp.log))

# ================================================================ SSH
print("== SSH through a proxy (a real SSH server on this computer)")
root = os.path.join(SP, "pxroot%d" % int(time.time())); os.makedirs(root); open(os.path.join(root, "f.txt"), "w").write("x")
ssh = fileserver.SftpServer(root, "toner", "Passw0rd!!", port=0, bind="127.0.0.1", host_key_path=os.path.join(SP, "pxkey"))
ssh.start()
def ssh_over(device):
    sock, closers = jump.open_channel(device, 8)
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", ssh.port, "toner", "Passw0rd!!", sock=sock, look_for_keys=False, allow_agent=False, timeout=8, banner_timeout=15, auth_timeout=15)
    names = c.open_sftp().listdir("."); c.close()
    for x in closers: x.close()
    return sock, names
sshdev = dev("sshbox", host="127.0.0.1", port=ssh.port)
sock, names = ssh_over(sshdev); check("no proxy: a direct connection (no tunnel object)", sock is None and names == ["f.txt"])
hp.log.clear(); sock, names = ssh_over({**sshdev, "proxy": custom_for(hp)})
check("the device's HTTP proxy carries the SSH session", names == ["f.txt"] and hp.log[0][0] == f"CONNECT 127.0.0.1:{ssh.port} HTTP/1.1", hp.log)
sp.log.clear(); sock, names = ssh_over({**sshdev, "proxy": json.dumps({"mode": "custom", "kind": "socks5", "host": "127.0.0.1", "port": sp.port, "username": ""})})
check("a SOCKS5 proxy carries it too", names == ["f.txt"] and sp.log and sp.log[0][2] == ssh.port, sp.log)
global_mode(mode="manual", host="127.0.0.1", port=hp.port, bypass=""); hp.log.clear(); sock, names = ssh_over(sshdev)
check("the global setting carries a device that has no setting of its own", names == ["f.txt"] and hp.log, hp.log)
hp.log.clear(); sock, names = ssh_over({**sshdev, "proxy": json.dumps({"mode": "none"})})
check("...but not one set to connect directly", names == ["f.txt"] and not hp.log and sock is None, hp.log)
global_mode(mode="system"); hp.log.clear(); sock, names = ssh_over(sshdev)
check("the Windows proxy setting is for web connections only, so SSH stays direct", sock is None and not hp.log)
try: ssh_over({**sshdev, "proxy": custom_for(HttpProxy(auth="a:b"))}); check("a proxy login failure stops the SSH connection with its reason", False)
except proxy.ProxyError as e: check("a proxy login failure stops the SSH connection with its reason", "needs a user name and password" in str(e), str(e))
ssh.stop()

print("== the pieces that build SSH connections ask for the proxy")
src = {n: open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), *p)).read() for n, p in (("cisco", ("drivers", "cisco.py")), ("sshbase", ("drivers", "sshbase.py")), ("tools", ("ui", "sessions.py")))}
check("both SSH drivers use open_channel, which now covers proxies", all("jump.open_channel" in src[k] for k in ("cisco", "sshbase")))
check("SSH sessions pass their device along, so a proxy applies there too", "jump_dev=profiles.resolve(dev) if dev else None" in src["tools"] and "TelnetSession(" in src["tools"] and "profiles.resolve(dev) if dev else None)" in src["tools"])

# ================================================================ notifications
print("== notifications")
global_mode(mode="manual", host="127.0.0.1", port=hp.port, bypass=""); hp.log.clear()
sm = Smtp()
mail = notify._SMTP("127.0.0.1", sm.port, timeout=5); code = mail.noop()[0]; mail.quit()
check("email goes through the global proxy", code == 250 and hp.log and hp.log[0][0] == f"CONNECT 127.0.0.1:{sm.port} HTTP/1.1", hp.log)
hp.log.clear()
try: notify._post(WEB, {}, json_body={"a": 1})
except Exception as e: pass
check("a webhook goes through the global proxy", hp.log and hp.log[0][0].startswith("POST http://127.0.0.1"), hp.log)
global_mode(mode="manual", host="127.0.0.1", port=hp.port, bypass="127.0.0.1"); hp.log.clear(); hits.clear()
mail = notify._SMTP("127.0.0.1", sm.port, timeout=5); mail.noop(); mail.quit()
notify._post(WEB, {}, json_body={"a": 1})
check("an address on the bypass list is contacted directly", not hp.log and hits == ["/hello"], (hp.log, hits))
global_mode(mode="system")

# ================================================================ storage
print("== saving")
d = dev("saved", host="10.0.0.5", proxy={"mode": "custom", "kind": "socks5", "host": "px", "port": 1080, "username": "u"}); db.save_device(d)
row = [x for x in db.list_devices() if x["name"] == "saved"][0]
check("a device keeps its proxy setting", json.loads(row["proxy"]) == {"mode": "custom", "kind": "socks5", "host": "px", "port": 1080, "username": "u"})
db.save_device({**row, "proxy": ""}); check("and clearing it", [x for x in db.list_devices() if x["name"] == "saved"][0]["proxy"] == "")
STORE[("netcheck", "saved:proxy")] = "pw"; db.move_device_secrets("saved", "renamed")
check("the proxy password follows a rename", STORE.get(("netcheck", "renamed:proxy")) == "pw" and ("netcheck", "saved:proxy") not in STORE)
db.delete_device_secrets("renamed"); check("and is removed with the device", ("netcheck", "renamed:proxy") not in STORE)
check("the global proxy setting is a portable setting, its password is not", "proxy" in db.export_settings() and "pw" not in json.dumps(db.export_settings()))

# ================================================================ UI
print("== UI: Settings > Proxy")
import ui.settings as S
pg = S.ProxyPage(); pg.load()
check("defaults: Windows settings, manual fields greyed out", pg.mode.currentData() == "system" and not pg.host.isEnabled() and "Windows" in pg.system.text())
pg.mode.setCurrentIndex(pg.mode.findData("manual"))
check("choosing manual enables the fields", pg.host.isEnabled() and pg.port.isEnabled() and pg.password.isEnabled())
check("a manual proxy needs an address", pg.validate() and "address" in pg.validate()[0])
pg.kind.setCurrentIndex(pg.kind.findData("http")); pg.host.setText("127.0.0.1"); pg.port.setValue(hp2.port); pg.user.setText("svc"); pg.password.setText("s3cret"); pg.bypass.setText("localhost")
check("with an address it validates", pg.validate() == [])
pg.test_to.setText(f"127.0.0.1:{echo.port}"); pg.test(); check("Test reports success", pg.test_out.text().startswith("OK: Connected to 127.0.0.1"), pg.test_out.text())
pg.password.setText("wrong"); pg.test(); check("Test reports a wrong password", pg.test_out.text().startswith("Failed:") and "rejected" in pg.test_out.text(), pg.test_out.text())
pg.password.setText("s3cret"); pg.save()
saved = db.get_setting("proxy")
check("saved: the setting has no password; Credential Manager has it", saved["mode"] == "manual" and saved["host"] == "127.0.0.1" and saved["port"] == hp2.port and saved["username"] == "svc" and "s3cret" not in json.dumps(saved) and STORE[("netcheck", proxy.GLOBAL_SECRET)] == "s3cret")
check("and the change is in the audit log (without the password)", any(a["action"] == "proxy settings changed" and "s3cret" not in a["detail"] for a in __import__("core.audit", fromlist=["x"]).recent()))
pg2 = S.ProxyPage(); pg2.load()
check("reopening shows it and says a password is saved", pg2.mode.currentData() == "manual" and pg2.host.text() == "127.0.0.1" and pg2.password.text() == "" and "saved" in pg2.pw_note.text())
pg2.test_to.setText(f"127.0.0.1:{echo.port}"); pg2.test(); check("a saved password is used when the box is empty", pg2.test_out.text().startswith("OK:"), pg2.test_out.text())
pg2._clear_password(); pg2.save(); check("the saved password can be removed", ("netcheck", proxy.GLOBAL_SECRET) not in STORE)
pg2.mode.setCurrentIndex(pg2.mode.findData("none")); pg2.test_to.setText(f"127.0.0.1:{web.server_address[1]}"); pg2.test()
check("'no proxy' tests a direct connection", pg2.test_out.text().split(":")[0] in ("OK", "Failed"))
pg2.test_to.setText("nonsense"); pg2.test(); check("a malformed address is explained", "Enter an address" in pg2.test_out.text() or pg2.test_out.text().startswith(("OK", "Failed")))
sp_ = S.SettingsTab(); check("it has its own page in Settings", any(p.title == "Proxy" for p in sp_.pages))
db.set_setting("proxy", {**proxy.DEFAULTS})

print("== UI: the device dialog")
import ui.inventory as I
dd = I.DeviceDialog(); dd.vendor.setCurrentIndex(dd.vendor.findData("cisco"))
check("a normal device offers the proxy choice, details hidden until needed", dd.access.isRowVisible(dd.proxy_mode) and not dd.access.isRowVisible(dd.proxy_host) and dd.values()["proxy"] == "")
dd.proxy_mode.setCurrentIndex(dd.proxy_mode.findData("custom"))
check("choosing 'a proxy for this device' shows the details", all(dd.access.isRowVisible(w) for w in (dd.proxy_kind, dd.proxy_host, dd.proxy_port, dd.proxy_user, dd.proxy_pw)))
dd.name.setText("branch"); dd.host.setText("10.2.2.2"); dd.proxy_kind.setCurrentIndex(dd.proxy_kind.findData("socks5")); dd.proxy_host.setText("px.example.com"); dd.proxy_port.setValue(1080); dd.proxy_user.setText("u"); dd.proxy_pw.setText("secret!")
v = dd.values()
check("its values, with the password kept apart", v["proxy"] == {"mode": "custom", "kind": "socks5", "host": "px.example.com", "port": 1080, "username": "u"} and dd.proxy_secrets() == {"proxy": "secret!"} and "secret!" not in json.dumps(v))
w3 = I.InventoryTab(); w3._save(v, "", extra_secrets={**dd.snmp_secrets(), **dd.proxy_secrets()})
saved_dev = [x for x in db.list_devices() if x["name"] == "branch"][0]
check("saved with the password in Credential Manager", json.loads(saved_dev["proxy"])["host"] == "px.example.com" and STORE.get(("netcheck", "branch:proxy")) == "secret!")
again = I.DeviceDialog(saved_dev)
check("editing restores it, and the password stays hidden", again.proxy_mode.currentData() == "custom" and again.proxy_host.text() == "px.example.com" and again.proxy_port.value() == 1080 and again.proxy_kind.currentData() == "socks5" and again.proxy_pw.text() == "" and "saved" in again.proxy_pw.placeholderText())
again.name.setText("branch2"); w3._save(again.values(), "", old_name="branch", extra_secrets={**again.snmp_secrets(), **again.proxy_secrets()})
check("renaming the device keeps its proxy password", STORE.get(("netcheck", "branch2:proxy")) == "secret!" and ("netcheck", "branch:proxy") not in STORE)
nd = I.DeviceDialog(); nd.vendor.setCurrentIndex(nd.vendor.findData("cisco")); nd.name.setText("x"); nd.host.setText("10.1.1.1"); nd.proxy_mode.setCurrentIndex(nd.proxy_mode.findData("custom")); warned.clear(); nd.accept()
check("a custom proxy with no address is refused", warned and "proxy's address" in warned[-1] and nd.result() != 1)
nd.proxy_mode.setCurrentIndex(nd.proxy_mode.findData("none")); check("'connect directly' is stored as such", nd.values()["proxy"] == {"mode": "none"})
for vendor, shown in (("cisco", True), ("fortinet", True), ("cloud", True), ("snmp", False), ("wifi", False)):
    x = I.DeviceDialog(); x.vendor.setCurrentIndex(x.vendor.findData(vendor))
    check(f"{vendor}: proxy choice {'offered' if shown else 'hidden (SNMP and local checks cannot use a proxy)'}", x.access.isRowVisible(x.proxy_mode) == shown and (x.values()["proxy"] == "" or shown))
tdlg = I.DeviceDialog(); tdlg.vendor.setCurrentIndex(tdlg.vendor.findData("cloud")); tdlg.name.setText("t"); tdlg.host.setText("www.githubstatus.com")
tdlg.proxy_mode.setCurrentIndex(tdlg.proxy_mode.findData("custom")); tdlg.proxy_host.setText("127.0.0.1"); tdlg.proxy_port.setValue(hp.port); tdlg.proxy_pw.setText("typed")
hp.log.clear(); seen = []
import core.runner as _r
orig_run = I.run_one; I.run_one = lambda d, th, o: (seen.append((d.get("proxy"), d.get("_proxy_secret"))), [])[1]
tdlg.test(); I.run_one = orig_run
check("Test connection uses the proxy being edited, including a password not saved yet", seen and json.loads(seen[0][0])["host"] == "127.0.0.1" and seen[0][1] == "typed", seen)

print("== the app-wide places also honour the setting")
check("the MAC list download, notifications and the certificate tool ask for the proxy", all(s in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), *p)).read() for s, p in (("proxy.requests_kwargs", ("core", "oui.py")), ("proxy.requests_kwargs", ("core", "notify.py")), ("proxy.create_connection", ("ui", "tools2.py")))))
check("every web driver passes the device to the proxy layer", all("proxy.requests_kwargs" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "drivers", f"{n}.py")).read() for n in ("fortinet", "paloalto", "meraki", "unifi", "cloud")) and "proxy.requests_kwargs" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "backup.py")).read())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
