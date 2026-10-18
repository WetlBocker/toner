# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Older devices (Cisco ASA and the like) that only offer ssh-rsa and SHA-1 key exchange, which paramiko 5 dropped.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, socket, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\legacy%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from core import legacyssh, nettools
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

RSA = paramiko.RSAKey.generate(2048)
ECDSA = paramiko.ECDSAKey.generate()

class Srv(paramiko.ServerInterface):
    def get_allowed_auths(self, u): return "password"
    def check_auth_password(self, u, p): return paramiko.AUTH_SUCCESSFUL if (u, p) == ("admin", "pw") else paramiko.AUTH_FAILED

class Device:
    """An SSH server that offers only the given key exchanges and host key types, like an older ASA."""
    def __init__(self, kex, key_types, keys):
        self.kex, self.key_types, self.keys, self.seen = kex, key_types, keys, []
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(8); self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while True:
            try: c, _ = self.sock.accept()
            except OSError: return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()
    def _serve(self, c):
        try:
            t = paramiko.Transport(c)
            for k in self.keys: t.add_server_key(k)
            so = t.get_security_options(); so.kex = self.kex; so.key_types = self.key_types
            t.start_server(server=Srv())
            self.seen.append((t.host_key_type, type(t.kex_engine).name if t.kex_engine else None))
            time.sleep(2); t.close()
        except Exception as e:
            self.seen.append(("error", str(e)))

def connect(dev):
    cl = paramiko.SSHClient(); cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect("127.0.0.1", port=dev.port, username="admin", password="pw", timeout=8, allow_agent=False, look_for_keys=False)
        t = cl.get_transport(); out = ("ok", t.host_key_type, t.get_remote_server_key().get_name())
    except Exception as e:
        out = ("error", type(e).__name__, str(e))
    cl.close()
    return out

print("== the lists")
T = paramiko.Transport
check("on from the start: ssh-rsa and the SHA-1 key exchanges are offered", legacyssh.enabled() and "ssh-rsa" in T._preferred_keys
      and "diffie-hellman-group14-sha1" in T._preferred_kex and "diffie-hellman-group1-sha1" in T._preferred_kex
      and "diffie-hellman-group-exchange-sha1" in T._preferred_kex)
check("but last, after every newer one", T._preferred_keys[-1] == "ssh-rsa" and T._preferred_keys[0] != "ssh-rsa"
      and list(T._preferred_kex[-3:]) == ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"],
      (T._preferred_keys, T._preferred_kex))
check("importing it twice does not list them twice", (legacyssh.enable(True), T._preferred_keys.count("ssh-rsa") == 1
      and T._preferred_kex.count("diffie-hellman-group14-sha1") == 1)[1])

print("== an older device: ssh-rsa with diffie-hellman-group14-sha1 (a Cisco ASA)")
asa = Device(("diffie-hellman-group14-sha1",), ("ssh-rsa",), [RSA])
r = connect(asa)
check("Toner connects and signs in", r[0] == "ok" and r[2] == "ssh-rsa", r)
check("using ssh-rsa (and group14-sha1, the only key exchange it offers)", asa.seen and asa.seen[-1][0] == "ssh-rsa", asa.seen)
old = Device(("diffie-hellman-group1-sha1",), ("ssh-rsa",), [RSA])
r = connect(old)
check("an even older one with diffie-hellman-group1-sha1 works too", r[0] == "ok" and old.seen[-1][0] == "ssh-rsa", (r, old.seen))

print("== a current device still uses current algorithms")
new = Device(tuple(k for k in T._preferred_kex), tuple(k for k in T._preferred_keys), [RSA, ECDSA])
r = connect(new)
check("a server that offers both agrees on the newer ones", r[0] == "ok" and new.seen[-1][0] != "ssh-rsa"
      and "sha1" not in (new.seen[-1][1] or ""), (r, new.seen))
rsa_only_modern = Device(("diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"), ("rsa-sha2-512", "ssh-rsa"), [RSA])
r = connect(rsa_only_modern)
check("an RSA key is signed with SHA-2 when the device can", r[0] == "ok" and rsa_only_modern.seen[-1][0] == "rsa-sha2-512",
      (r, rsa_only_modern.seen))

print("== turned off in Settings > Security")
db.set_setting("ssh_legacy_algorithms", False)
check("apply() follows the setting", legacyssh.apply() is False and not legacyssh.enabled() and "ssh-rsa" not in T._preferred_keys)
asa2 = Device(("diffie-hellman-group14-sha1",), ("ssh-rsa",), [RSA])
r = connect(asa2)
check("then the ASA fails as it did before (netmiko words it 'Incompatible ssh peer')", r[0] == "error"
      and ("Incompatible" in r[2] or "No existing session" in r[2]), r)
db.set_setting("ssh_legacy_algorithms", True)
check("and on again", legacyssh.apply() is True and legacyssh.enabled())
r = connect(asa2)
check("after which it connects", r[0] == "ok", r)

print("== the Security page")
from PySide6.QtWidgets import QApplication
app = QApplication([])
from ui.settings_pages.security import SecurityPage
page = SecurityPage(); page.load()
check("it has the setting, on", page.legacy.isChecked() and "older" in page.legacy.text().lower())
page.legacy.setChecked(False); page.save()
check("unticking and saving turns them off at once", db.get_setting("ssh_legacy_algorithms") is False and not legacyssh.enabled())
page.legacy.setChecked(True); page.save()
check("ticking it turns them back on", db.get_setting("ssh_legacy_algorithms") is True and legacyssh.enabled())

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
