# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, select, socket, sys, threading, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\jp%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, jump, profiles, nettools
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
import paramiko

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

HOSTKEY = paramiko.RSAKey.generate(2048)

class Srv(paramiko.ServerInterface):
    def __init__(self, user, pw, forward=False, banner=""):
        self.user, self.pw, self.forward, self.banner = user, pw, forward, banner
        self.dest = {}
        self.cmd = threading.Event()
    def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if (u, p) == (self.user, self.pw) else paramiko.AUTH_FAILED
    def get_allowed_auths(self, u): return "password"
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self, channel, command):
        def go():
            time.sleep(0.3)
            channel.sendall(f"{self.banner}:{command.decode()}\n".encode()); channel.send_exit_status(0); channel.close()
        threading.Thread(target=go, daemon=True).start()
        return True
    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if not self.forward: return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.dest[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

def serve(srv):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(10)
    def pump(chan, dest):
        try:
            up = socket.create_connection(dest, timeout=5)
        except OSError:
            chan.close(); return
        def a():
            try:
                while True:
                    d = chan.recv(32768)
                    if not d: break
                    up.sendall(d)
            except Exception: pass
            try: up.shutdown(socket.SHUT_WR)
            except OSError: pass
        threading.Thread(target=a, daemon=True).start()
        try:
            while True:
                d = up.recv(32768)
                if not d: break
                chan.sendall(d)
        except Exception: pass
        chan.close()
    def loop():
        while True:
            try: c, _ = s.accept()
            except OSError: return
            def handle(c=c):
                t = paramiko.Transport(c); t.add_server_key(HOSTKEY)
                try: t.start_server(server=srv)
                except Exception: return
                while t.is_active():
                    ch = t.accept(1)
                    if ch is None: continue
                    dest = srv.dest.pop(ch.get_id(), None)
                    if dest: threading.Thread(target=pump, args=(ch, dest), daemon=True).start()
            threading.Thread(target=handle, daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1]

TARGET = serve(Srv("admin", "devpass", banner="target"))
JUMP = serve(Srv("jumpuser", "jumppass", forward=True, banner="jump"))
NOFWD = serve(Srv("jumpuser", "jumppass", forward=False, banner="jump"))

def dev(name, host="127.0.0.1", port=0, **kw):
    d = dict(name=name, vendor="cisco", host=host, port=port, platform="cisco_ios", username="", site="default", verify_ssl=0, ha_expected=0, enabled=1, location="", details="", folder_id=None); d.update(kw)
    db.save_device(d); return [x for x in db.list_devices() if x["name"] == name][0]

db.set_setting("hostkey_mode", "Always trust")
print("== jump host plumbing")
_d = dev("direct"); check("no jump set -> direct", jump.spec(_d) is None and jump.open_channel(_d) == (None, []))
bastion = dev("bastion", port=JUMP, username="jumpuser"); db.set_secret("bastion", "jumppass")
behind = dev("behind", port=TARGET, username="admin", jump={"device": "bastion"}); db.set_secret("behind", "devpass")
check("jump spec is read from the device", jump.spec(behind) == {"device": "bastion"})
chan, closers = jump.open_channel(behind, 5)
check("a channel to the target is opened through the bastion", chan is not None and len(closers) == 2)
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("127.0.0.1", port=TARGET, username="admin", password="devpass", sock=chan, timeout=5, allow_agent=False, look_for_keys=False)
_, out, _ = c.exec_command("show version"); text = out.read().decode()
check("SSH to the device works over that channel (the device answers, not the bastion)", text.strip() == "target:show version", text)
c.close()
for x in closers:
    try: x.close()
    except Exception: pass

print("== failures are explained")
dev("badjump", port=TARGET, jump={"device": "nonexistent"})
try: jump.open_channel([x for x in db.list_devices() if x["name"] == "badjump"][0], 3); check("missing jump host", False)
except ValueError as e: check("a jump host that left the inventory is named", "nonexistent" in str(e), e)
db.set_secret("bastion", "wrong")
try: jump.open_channel(behind, 3); check("wrong bastion password", False)
except ConnectionError as e: check("a failing bastion login is reported with its name", "bastion" in str(e) and "Authentication" in str(e), e)
db.set_secret("bastion", "jumppass")
nf = dev("nofwd", port=NOFWD, username="jumpuser"); db.set_secret("nofwd", "jumppass")
via_nofwd = dev("behind2", port=TARGET, username="admin", jump={"device": "nofwd"})
try: jump.open_channel(via_nofwd, 3); check("bastion refusing forwarding", False)
except ConnectionError as e: check("a bastion that forbids forwarding is reported", "bastion" not in str(e) and "nofwd" in str(e), e)
selfref = dev("loopy", port=TARGET, jump={"device": "loopy"})
try: jump.open_channel(selfref, 3); check("a device cannot be its own jump host", False)
except ValueError: check("a device cannot be its own jump host", True)

print("== drivers use it")
from drivers import DRIVERS
import drivers.cisco as DC, drivers.sshbase as SB
seen = {}
class FakeHandler:
    def __init__(self, **kw): seen.update(kw); self.closed = False
    def __enter__(self): return self
    def __exit__(self, *a): self.closed = True; return False
DC.ConnectHandler = FakeHandler; SB.ConnectHandler = FakeHandler
drv = DRIVERS["cisco"](behind, {}, {"ssh_timeout": 5}); drv.plat = "cisco_ios"
with drv.connect() as h:
    pass
check("the Cisco driver passes the channel to netmiko as 'sock'", seen.get("sock") is not None and seen["host"] == "127.0.0.1")
seen.clear()
drv = DRIVERS["juniper"](behind, {}, {"ssh_timeout": 5}); drv.plat = "juniper_junos"
with drv.connect() as h:
    pass
check("so do the other SSH drivers", seen.get("sock") is not None)
seen.clear()
drv = DRIVERS["cisco"](dev("plain", port=TARGET), {}, {"ssh_timeout": 5}); drv.plat = "cisco_ios"
with drv.connect() as h:
    pass
check("devices without a jump host connect directly (no sock)", "sock" not in seen)

print("== the SSH console")
rec = {}
class FakeClient(paramiko.SSHClient):
    def connect(self, *a, **k): rec.update(k); raise OSError("stop here")
import core.nettools as NT
orig = NT.paramiko.SSHClient
NT.paramiko.SSHClient = FakeClient
real_open = jump.open_channel; jump.open_channel = lambda dev, timeout=15: ("CHANNEL", [])
sess = NT.SshSession("127.0.0.1", TARGET, "admin", "devpass", jump_dev=profiles.resolve(behind), hostkey_mode="Always trust", timeout=5)
reasons = []; sess.closed.connect(reasons.append); sess.run()
NT.paramiko.SSHClient = orig; jump.open_channel = real_open
check("the console connects through the jump host's channel", rec.get("sock") == "CHANNEL", rec.keys())
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
